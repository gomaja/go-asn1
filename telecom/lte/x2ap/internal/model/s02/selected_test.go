// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s02

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
func TestSelectedCoMPInformationStartTimeExtIEsValue(t *testing.T) {
	var absent *CoMPInformationStartTimeExtIEsValue
	selectedAssert(t, absent)
	v := CoMPInformationStartTimeExtIEsValue{}
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
	t.Logf("union CoMPInformationStartTimeExtIEsValue: 0 synthetic rows")
}
func TestSelectedCompleteFailureCauseInformationItemExtIEsValue(t *testing.T) {
	var absent *CompleteFailureCauseInformationItemExtIEsValue
	selectedAssert(t, absent)
	v := CompleteFailureCauseInformationItemExtIEsValue{}
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
	t.Logf("union CompleteFailureCauseInformationItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedCompositeAvailableCapacityExtIEsValue(t *testing.T) {
	var absent *CompositeAvailableCapacityExtIEsValue
	selectedAssert(t, absent)
	v := CompositeAvailableCapacityExtIEsValue{}
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
	t.Logf("union CompositeAvailableCapacityExtIEsValue: 0 synthetic rows")
}
func TestSelectedCompositeAvailableCapacityGroupExtIEsValue(t *testing.T) {
	var absent *CompositeAvailableCapacityGroupExtIEsValue
	selectedAssert(t, absent)
	v := CompositeAvailableCapacityGroupExtIEsValue{}
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
	t.Logf("union CompositeAvailableCapacityGroupExtIEsValue: 0 synthetic rows")
}
func TestSelectedCriticalityDiagnosticsExtIEsValue(t *testing.T) {
	var absent *CriticalityDiagnosticsExtIEsValue
	selectedAssert(t, absent)
	v := CriticalityDiagnosticsExtIEsValue{}
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
	t.Logf("union CriticalityDiagnosticsExtIEsValue: 0 synthetic rows")
}
func TestSelectedCriticalityDiagnosticsIEListExtIEsValue(t *testing.T) {
	var absent *CriticalityDiagnosticsIEListExtIEsValue
	selectedAssert(t, absent)
	v := CriticalityDiagnosticsIEListExtIEsValue{}
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
	t.Logf("union CriticalityDiagnosticsIEListExtIEsValue: 0 synthetic rows")
}
func TestSelectedDAPSRequestInfoExtIEsValue(t *testing.T) {
	var absent *DAPSRequestInfoExtIEsValue
	selectedAssert(t, absent)
	v := DAPSRequestInfoExtIEsValue{}
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
	t.Logf("union DAPSRequestInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedDAPSResponseInfoExtIEsValue(t *testing.T) {
	var absent *DAPSResponseInfoExtIEsValue
	selectedAssert(t, absent)
	v := DAPSResponseInfoExtIEsValue{}
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
	t.Logf("union DAPSResponseInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedDLDiscardingExtIEsValue(t *testing.T) {
	var absent *DLDiscardingExtIEsValue
	selectedAssert(t, absent)
	v := DLDiscardingExtIEsValue{}
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
	t.Logf("union DLDiscardingExtIEsValue: 0 synthetic rows")
}
func TestSelectedDataTrafficResourceIndicationExtIEsValue(t *testing.T) {
	var absent *DataTrafficResourceIndicationExtIEsValue
	selectedAssert(t, absent)
	v := DataTrafficResourceIndicationExtIEsValue{}
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
	t.Logf("union DataTrafficResourceIndicationExtIEsValue: 0 synthetic rows")
}
func TestSelectedDeliveryStatusExtIEsValue(t *testing.T) {
	var absent *DeliveryStatusExtIEsValue
	selectedAssert(t, absent)
	v := DeliveryStatusExtIEsValue{}
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
	t.Logf("union DeliveryStatusExtIEsValue: 0 synthetic rows")
}
func TestSelectedDynamicNAICSInformationExtIEsValue(t *testing.T) {
	var absent *DynamicNAICSInformationExtIEsValue
	selectedAssert(t, absent)
	v := DynamicNAICSInformationExtIEsValue{}
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
	t.Logf("union DynamicNAICSInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedECGIExtIEsValue(t *testing.T) {
	var absent *ECGIExtIEsValue
	selectedAssert(t, absent)
	v := ECGIExtIEsValue{}
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
	t.Logf("union ECGIExtIEsValue: 0 synthetic rows")
}
func TestSelectedENBENDCConfigUpdateAckIEValue(t *testing.T) {
	var absent *ENBENDCConfigUpdateAckIEValue
	selectedAssert(t, absent)
	v := ENBENDCConfigUpdateAckIEValue{}
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
	t.Logf("union ENBENDCConfigUpdateAckIEValue: 0 synthetic rows")
}
func TestSelectedENDCResourceConfigurationExtIEsValue(t *testing.T) {
	var absent *ENDCResourceConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := ENDCResourceConfigurationExtIEsValue{}
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
	t.Logf("union ENDCResourceConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABActivityNotifyItemExtIEsValue(t *testing.T) {
	var absent *ERABActivityNotifyItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABActivityNotifyItemExtIEsValue{}
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
	t.Logf("union ERABActivityNotifyItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABItemExtIEsValue(t *testing.T) {
	var absent *ERABItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABItemExtIEsValue{}
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
	t.Logf("union ERABItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABUsageReportItemExtIEsValue(t *testing.T) {
	var absent *ERABUsageReportItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABUsageReportItemExtIEsValue{}
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
	t.Logf("union ERABUsageReportItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBModAckItemExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBModAckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBModAckItemExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeAddedSgNBModAckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedModAckItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedModAckItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedModAckItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeModifiedModAckItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedModAckItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedModAckItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedModAckItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeModifiedModAckItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModConfItemExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModConfItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModConfItemExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModConfItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPpresentExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeReleasedModAckItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeReleasedModAckItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeReleasedModAckItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeReleasedModAckItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeReleasedModAckItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeReleasedModAckItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeReleasedModAckItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeReleasedModAckItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsAdmittedToBeReleasedSgNBRelReqAckItemExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeReleasedSgNBRelReqAckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeReleasedSgNBRelReqAckItemExtIEsValue{}
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
	t.Logf("union ERABsAdmittedToBeReleasedSgNBRelReqAckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsDataForwardingAddressItemExtIEsValue(t *testing.T) {
	var absent *ERABsDataForwardingAddressItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsDataForwardingAddressItemExtIEsValue{}
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
	t.Logf("union ERABsDataForwardingAddressItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsSubjectToCounterCheckItemExtIEsValue(t *testing.T) {
	var absent *ERABsSubjectToCounterCheckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsSubjectToCounterCheckItemExtIEsValue{}
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
	t.Logf("union ERABsSubjectToCounterCheckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsSubjectToDLDiscardingItemExtIEsValue(t *testing.T) {
	var absent *ERABsSubjectToDLDiscardingItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsSubjectToDLDiscardingItemExtIEsValue{}
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
	t.Logf("union ERABsSubjectToDLDiscardingItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsSubjectToEarlyStatusTransferItemExtIEsValue(t *testing.T) {
	var absent *ERABsSubjectToEarlyStatusTransferItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsSubjectToEarlyStatusTransferItemExtIEsValue{}
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
	t.Logf("union ERABsSubjectToEarlyStatusTransferItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsSubjectToSgNBCounterCheckItemExtIEsValue(t *testing.T) {
	var absent *ERABsSubjectToSgNBCounterCheckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsSubjectToSgNBCounterCheckItemExtIEsValue{}
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
	t.Logf("union ERABsSubjectToSgNBCounterCheckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBAddReqAckItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBAddReqAckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBAddReqAckItemExtIEsValue{}
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
	t.Logf("union ERABsToBeAddedSgNBAddReqAckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBAddReqItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBAddReqItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBAddReqItemExtIEsValue{}
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
	t.Logf("union ERABsToBeAddedSgNBAddReqItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBModAckItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBModAckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBModAckItemExtIEsValue{}
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
	t.Logf("union ERABsToBeAddedSgNBModAckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBModReqItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBModReqItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBModReqItemExtIEsValue{}
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
	t.Logf("union ERABsToBeAddedSgNBModReqItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeModifiedModReqItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedModReqItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedModReqItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeModifiedModReqItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeModifiedModReqItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedModReqItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedModReqItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeModifiedModReqItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqItemExtIEsValue{}
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
	t.Logf("union ERABsToBeModifiedSgNBModReqItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqdItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqdItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqdItemExtIEsValue{}
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
	t.Logf("union ERABsToBeModifiedSgNBModReqdItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedModReqItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedModReqItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedModReqItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedModReqItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedModReqItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedModReqItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedModReqItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedModReqItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedModReqdItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedModReqdItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedModReqdItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedModReqdItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelConfItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelConfItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelConfItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedRelConfItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelConfItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelConfItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelConfItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedRelConfItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelReqItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelReqItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelReqItemSCGBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedRelReqItemSCGBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelReqItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelReqItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelReqItemSplitBearerExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedRelReqItemSplitBearerExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBChaConfItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBChaConfItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBChaConfItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBChaConfItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBChaConfItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBChaConfItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBChaConfItemSgNBPDCPnotpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBChaConfItemSgNBPDCPnotpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModAckItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModAckItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModAckItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBModAckItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBModReqItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBModReqItemSgNBPDCPpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelConfItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelConfItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelConfItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelConfItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelConfItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelConfItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelConfItemSgNBPDCPnotpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelConfItemSgNBPDCPnotpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelConfItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelConfItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelConfItemSgNBPDCPpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelConfItemSgNBPDCPpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelReqItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqItemSgNBPDCPnotpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelReqItemSgNBPDCPnotpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqItemSgNBPDCPpresentExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelReqItemSgNBPDCPpresentExtIEsValue: 0 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqdItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqdItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqdItemExtIEsValue{}
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
	t.Logf("union ERABsToBeReleasedSgNBRelReqdItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedEnhancedRNTPExtIEsValue(t *testing.T) {
	var absent *EnhancedRNTPExtIEsValue
	selectedAssert(t, absent)
	v := EnhancedRNTPExtIEsValue{}
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
	t.Logf("union EnhancedRNTPExtIEsValue: 0 synthetic rows")
}
func TestSelectedEnhancedRNTPStartTimeExtIEsValue(t *testing.T) {
	var absent *EnhancedRNTPStartTimeExtIEsValue
	selectedAssert(t, absent)
	v := EnhancedRNTPStartTimeExtIEsValue{}
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
	t.Logf("union EnhancedRNTPStartTimeExtIEsValue: 0 synthetic rows")
}
func TestSelectedExpectedUEActivityBehaviourExtIEsValue(t *testing.T) {
	var absent *ExpectedUEActivityBehaviourExtIEsValue
	selectedAssert(t, absent)
	v := ExpectedUEActivityBehaviourExtIEsValue{}
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
	t.Logf("union ExpectedUEActivityBehaviourExtIEsValue: 0 synthetic rows")
}
func TestSelectedExpectedUEBehaviourExtIEsValue(t *testing.T) {
	var absent *ExpectedUEBehaviourExtIEsValue
	selectedAssert(t, absent)
	v := ExpectedUEBehaviourExtIEsValue{}
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
	t.Logf("union ExpectedUEBehaviourExtIEsValue: 0 synthetic rows")
}
