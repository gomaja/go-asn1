// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s01

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
func TestSelectedActivatedCellListItemExtIEsValue(t *testing.T) {
	var absent *ActivatedCellListItemExtIEsValue
	selectedAssert(t, absent)
	v := ActivatedCellListItemExtIEsValue{}
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
	t.Logf("union ActivatedCellListItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedActivatedNRCellListItemExtIEsValue(t *testing.T) {
	var absent *ActivatedNRCellListItemExtIEsValue
	selectedAssert(t, absent)
	v := ActivatedNRCellListItemExtIEsValue{}
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
	t.Logf("union ActivatedNRCellListItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedAdditionalListofForwardingGTPTunnelEndpointItemExtIEsValue(t *testing.T) {
	var absent *AdditionalListofForwardingGTPTunnelEndpointItemExtIEsValue
	selectedAssert(t, absent)
	v := AdditionalListofForwardingGTPTunnelEndpointItemExtIEsValue{}
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
	t.Logf("union AdditionalListofForwardingGTPTunnelEndpointItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedAdditionalMeasurementTimingConfigurationItemExtIEsValue(t *testing.T) {
	var absent *AdditionalMeasurementTimingConfigurationItemExtIEsValue
	selectedAssert(t, absent)
	v := AdditionalMeasurementTimingConfigurationItemExtIEsValue{}
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
	t.Logf("union AdditionalMeasurementTimingConfigurationItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedAdditionalSpecialSubframeExtensionInfoExtIEsValue(t *testing.T) {
	var absent *AdditionalSpecialSubframeExtensionInfoExtIEsValue
	selectedAssert(t, absent)
	v := AdditionalSpecialSubframeExtensionInfoExtIEsValue{}
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
	t.Logf("union AdditionalSpecialSubframeExtensionInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedAdditionalSpecialSubframeInfoExtIEsValue(t *testing.T) {
	var absent *AdditionalSpecialSubframeInfoExtIEsValue
	selectedAssert(t, absent)
	v := AdditionalSpecialSubframeInfoExtIEsValue{}
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
	t.Logf("union AdditionalSpecialSubframeInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedAllocationAndRetentionPriorityExtIEsValue(t *testing.T) {
	var absent *AllocationAndRetentionPriorityExtIEsValue
	selectedAssert(t, absent)
	v := AllocationAndRetentionPriorityExtIEsValue{}
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
	t.Logf("union AllocationAndRetentionPriorityExtIEsValue: 0 synthetic rows")
}
func TestSelectedBPLMNIDInfoEUTRAItemExtIEsValue(t *testing.T) {
	var absent *BPLMNIDInfoEUTRAItemExtIEsValue
	selectedAssert(t, absent)
	v := BPLMNIDInfoEUTRAItemExtIEsValue{}
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
	t.Logf("union BPLMNIDInfoEUTRAItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedBPLMNIDInfoNRItemExtIEsValue(t *testing.T) {
	var absent *BPLMNIDInfoNRItemExtIEsValue
	selectedAssert(t, absent)
	v := BPLMNIDInfoNRItemExtIEsValue{}
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
	t.Logf("union BPLMNIDInfoNRItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedBandInfoExtIEsValue(t *testing.T) {
	var absent *BandInfoExtIEsValue
	selectedAssert(t, absent)
	v := BandInfoExtIEsValue{}
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
	t.Logf("union BandInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedBluetoothMeasurementConfigurationExtIEsValue(t *testing.T) {
	var absent *BluetoothMeasurementConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := BluetoothMeasurementConfigurationExtIEsValue{}
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
	t.Logf("union BluetoothMeasurementConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedCHOTimeBasedInformationExtIEsValue(t *testing.T) {
	var absent *CHOTimeBasedInformationExtIEsValue
	selectedAssert(t, absent)
	v := CHOTimeBasedInformationExtIEsValue{}
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
	t.Logf("union CHOTimeBasedInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedCHOinformationACKExtIEsValue(t *testing.T) {
	var absent *CHOinformationACKExtIEsValue
	selectedAssert(t, absent)
	v := CHOinformationACKExtIEsValue{}
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
	t.Logf("union CHOinformationACKExtIEsValue: 0 synthetic rows")
}
func TestSelectedCHOinformationAddReqExtIEsValue(t *testing.T) {
	var absent *CHOinformationAddReqExtIEsValue
	selectedAssert(t, absent)
	v := CHOinformationAddReqExtIEsValue{}
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
	t.Logf("union CHOinformationAddReqExtIEsValue: 0 synthetic rows")
}
func TestSelectedCHOinformationModReqExtIEsValue(t *testing.T) {
	var absent *CHOinformationModReqExtIEsValue
	selectedAssert(t, absent)
	v := CHOinformationModReqExtIEsValue{}
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
	t.Logf("union CHOinformationModReqExtIEsValue: 0 synthetic rows")
}
func TestSelectedCNTypeRestrictionsItemExtIEsValue(t *testing.T) {
	var absent *CNTypeRestrictionsItemExtIEsValue
	selectedAssert(t, absent)
	v := CNTypeRestrictionsItemExtIEsValue{}
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
	t.Logf("union CNTypeRestrictionsItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCOUNTValueExtendedExtIEsValue(t *testing.T) {
	var absent *COUNTValueExtendedExtIEsValue
	selectedAssert(t, absent)
	v := COUNTValueExtendedExtIEsValue{}
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
	t.Logf("union COUNTValueExtendedExtIEsValue: 0 synthetic rows")
}
func TestSelectedCOUNTvalueExtIEsValue(t *testing.T) {
	var absent *COUNTvalueExtIEsValue
	selectedAssert(t, absent)
	v := COUNTvalueExtIEsValue{}
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
	t.Logf("union COUNTvalueExtIEsValue: 0 synthetic rows")
}
func TestSelectedCOUNTvaluePDCPSNlength18ExtIEsValue(t *testing.T) {
	var absent *COUNTvaluePDCPSNlength18ExtIEsValue
	selectedAssert(t, absent)
	v := COUNTvaluePDCPSNlength18ExtIEsValue{}
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
	t.Logf("union COUNTvaluePDCPSNlength18ExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPACcandidatePSCellsItemExtIEsValue(t *testing.T) {
	var absent *CPACcandidatePSCellsItemExtIEsValue
	selectedAssert(t, absent)
	v := CPACcandidatePSCellsItemExtIEsValue{}
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
	t.Logf("union CPACcandidatePSCellsItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPACinformationREQDExtIEsValue(t *testing.T) {
	var absent *CPACinformationREQDExtIEsValue
	selectedAssert(t, absent)
	v := CPACinformationREQDExtIEsValue{}
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
	t.Logf("union CPACinformationREQDExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPAinformationMODACKExtIEsValue(t *testing.T) {
	var absent *CPAinformationMODACKExtIEsValue
	selectedAssert(t, absent)
	v := CPAinformationMODACKExtIEsValue{}
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
	t.Logf("union CPAinformationMODACKExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPAinformationMODExtIEsValue(t *testing.T) {
	var absent *CPAinformationMODExtIEsValue
	selectedAssert(t, absent)
	v := CPAinformationMODExtIEsValue{}
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
	t.Logf("union CPAinformationMODExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPAinformationREQACKExtIEsValue(t *testing.T) {
	var absent *CPAinformationREQACKExtIEsValue
	selectedAssert(t, absent)
	v := CPAinformationREQACKExtIEsValue{}
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
	t.Logf("union CPAinformationREQACKExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPAinformationREQExtIEsValue(t *testing.T) {
	var absent *CPAinformationREQExtIEsValue
	selectedAssert(t, absent)
	v := CPAinformationREQExtIEsValue{}
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
	t.Logf("union CPAinformationREQExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCTargetSgNBConfItemExtIEsValue(t *testing.T) {
	var absent *CPCTargetSgNBConfItemExtIEsValue
	selectedAssert(t, absent)
	v := CPCTargetSgNBConfItemExtIEsValue{}
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
	t.Logf("union CPCTargetSgNBConfItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCTargetSgNBModItemExtIEsValue(t *testing.T) {
	var absent *CPCTargetSgNBModItemExtIEsValue
	selectedAssert(t, absent)
	v := CPCTargetSgNBModItemExtIEsValue{}
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
	t.Logf("union CPCTargetSgNBModItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCTargetSgNBReqdItemExtIEsValue(t *testing.T) {
	var absent *CPCTargetSgNBReqdItemExtIEsValue
	selectedAssert(t, absent)
	v := CPCTargetSgNBReqdItemExtIEsValue{}
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
	t.Logf("union CPCTargetSgNBReqdItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCinformationCONFExtIEsValue(t *testing.T) {
	var absent *CPCinformationCONFExtIEsValue
	selectedAssert(t, absent)
	v := CPCinformationCONFExtIEsValue{}
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
	t.Logf("union CPCinformationCONFExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCinformationNOTIFYExtIEsValue(t *testing.T) {
	var absent *CPCinformationNOTIFYExtIEsValue
	selectedAssert(t, absent)
	v := CPCinformationNOTIFYExtIEsValue{}
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
	t.Logf("union CPCinformationNOTIFYExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCinformationREQDExtIEsValue(t *testing.T) {
	var absent *CPCinformationREQDExtIEsValue
	selectedAssert(t, absent)
	v := CPCinformationREQDExtIEsValue{}
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
	t.Logf("union CPCinformationREQDExtIEsValue: 0 synthetic rows")
}
func TestSelectedCPCupdateMODExtIEsValue(t *testing.T) {
	var absent *CPCupdateMODExtIEsValue
	selectedAssert(t, absent)
	v := CPCupdateMODExtIEsValue{}
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
	t.Logf("union CPCupdateMODExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIRSMTCConfigurationItemExtIEsValue(t *testing.T) {
	var absent *CSIRSMTCConfigurationItemExtIEsValue
	selectedAssert(t, absent)
	v := CSIRSMTCConfigurationItemExtIEsValue{}
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
	t.Logf("union CSIRSMTCConfigurationItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIRSMTCNeighbourItemExtIEsValue(t *testing.T) {
	var absent *CSIRSMTCNeighbourItemExtIEsValue
	selectedAssert(t, absent)
	v := CSIRSMTCNeighbourItemExtIEsValue{}
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
	t.Logf("union CSIRSMTCNeighbourItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIRSNeighbourItemExtIEsValue(t *testing.T) {
	var absent *CSIRSNeighbourItemExtIEsValue
	selectedAssert(t, absent)
	v := CSIRSNeighbourItemExtIEsValue{}
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
	t.Logf("union CSIRSNeighbourItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIReportListExtIEsValue(t *testing.T) {
	var absent *CSIReportListExtIEsValue
	selectedAssert(t, absent)
	v := CSIReportListExtIEsValue{}
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
	t.Logf("union CSIReportListExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIReportPerCSIProcessExtIEsValue(t *testing.T) {
	var absent *CSIReportPerCSIProcessExtIEsValue
	selectedAssert(t, absent)
	v := CSIReportPerCSIProcessExtIEsValue{}
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
	t.Logf("union CSIReportPerCSIProcessExtIEsValue: 0 synthetic rows")
}
func TestSelectedCSIReportPerCSIProcessItemExtIEsValue(t *testing.T) {
	var absent *CSIReportPerCSIProcessItemExtIEsValue
	selectedAssert(t, absent)
	v := CSIReportPerCSIProcessItemExtIEsValue{}
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
	t.Logf("union CSIReportPerCSIProcessItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellBasedMDTExtIEsValue(t *testing.T) {
	var absent *CellBasedMDTExtIEsValue
	selectedAssert(t, absent)
	v := CellBasedMDTExtIEsValue{}
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
	t.Logf("union CellBasedMDTExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellBasedQMCExtIEsValue(t *testing.T) {
	var absent *CellBasedQMCExtIEsValue
	selectedAssert(t, absent)
	v := CellBasedQMCExtIEsValue{}
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
	t.Logf("union CellBasedQMCExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellMeasurementResultEUTRAENDCItemExtIEsValue(t *testing.T) {
	var absent *CellMeasurementResultEUTRAENDCItemExtIEsValue
	selectedAssert(t, absent)
	v := CellMeasurementResultEUTRAENDCItemExtIEsValue{}
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
	t.Logf("union CellMeasurementResultEUTRAENDCItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellMeasurementResultNRENDCItemExtIEsValue(t *testing.T) {
	var absent *CellMeasurementResultNRENDCItemExtIEsValue
	selectedAssert(t, absent)
	v := CellMeasurementResultNRENDCItemExtIEsValue{}
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
	t.Logf("union CellMeasurementResultNRENDCItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellReplacingInfoExtIEsValue(t *testing.T) {
	var absent *CellReplacingInfoExtIEsValue
	selectedAssert(t, absent)
	v := CellReplacingInfoExtIEsValue{}
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
	t.Logf("union CellReplacingInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellToReportEUTRAENDCItemExtIEsValue(t *testing.T) {
	var absent *CellToReportEUTRAENDCItemExtIEsValue
	selectedAssert(t, absent)
	v := CellToReportEUTRAENDCItemExtIEsValue{}
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
	t.Logf("union CellToReportEUTRAENDCItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellToReportItemExtIEsValue(t *testing.T) {
	var absent *CellToReportItemExtIEsValue
	selectedAssert(t, absent)
	v := CellToReportItemExtIEsValue{}
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
	t.Logf("union CellToReportItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellToReportNRENDCItemExtIEsValue(t *testing.T) {
	var absent *CellToReportNRENDCItemExtIEsValue
	selectedAssert(t, absent)
	v := CellToReportNRENDCItemExtIEsValue{}
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
	t.Logf("union CellToReportNRENDCItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellTypeExtIEsValue(t *testing.T) {
	var absent *CellTypeExtIEsValue
	selectedAssert(t, absent)
	v := CellTypeExtIEsValue{}
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
	t.Logf("union CellTypeExtIEsValue: 0 synthetic rows")
}
func TestSelectedCellandCapacityAssistInfoExtIEsValue(t *testing.T) {
	var absent *CellandCapacityAssistInfoExtIEsValue
	selectedAssert(t, absent)
	v := CellandCapacityAssistInfoExtIEsValue{}
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
	t.Logf("union CellandCapacityAssistInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedCoMPHypothesisSetItemExtIEsValue(t *testing.T) {
	var absent *CoMPHypothesisSetItemExtIEsValue
	selectedAssert(t, absent)
	v := CoMPHypothesisSetItemExtIEsValue{}
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
	t.Logf("union CoMPHypothesisSetItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCoMPInformationExtIEsValue(t *testing.T) {
	var absent *CoMPInformationExtIEsValue
	selectedAssert(t, absent)
	v := CoMPInformationExtIEsValue{}
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
	t.Logf("union CoMPInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedCoMPInformationItemExtIEsValue(t *testing.T) {
	var absent *CoMPInformationItemExtIEsValue
	selectedAssert(t, absent)
	v := CoMPInformationItemExtIEsValue{}
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
	t.Logf("union CoMPInformationItemExtIEsValue: 0 synthetic rows")
}
