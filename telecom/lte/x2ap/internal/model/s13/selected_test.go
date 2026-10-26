// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s13

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
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
func TestSelectedCellActivationResponseIEValue(t *testing.T) {
	var absent *CellActivationResponseIEValue
	selectedAssert(t, absent)
	v := CellActivationResponseIEValue{}
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
	{
		v := CellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(58)
		selectedAssert(t, &v)
		v.rowActivatedCellList = new(s06.ActivatedCellList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellActivationResponseIEValue: 2 synthetic rows")
}
func TestSelectedENDCCellActivationResponseIEValue(t *testing.T) {
	var absent *ENDCCellActivationResponseIEValue
	selectedAssert(t, absent)
	v := ENDCCellActivationResponseIEValue{}
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
	{
		v := ENDCCellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(268)
		selectedAssert(t, &v)
		v.rowActivatedNRCellList = new(s06.ActivatedNRCellList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(256)
		selectedAssert(t, &v)
		v.rowActivationID = new(s00.ActivationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationResponseIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCCellActivationResponseIEValue: 4 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBChaConfItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBChaConfItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBChaConfItemIEValue{}
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
	{
		v := ERABsToBeReleasedSgNBChaConfItemIEValue{}
		v.id = s00.ProtocolIEID(230)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBChaConfItem = new(ERABsToBeReleasedSgNBChaConfItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBChaConfItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEsValue{}
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
	{
		v := ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(441)
		selectedAssert(t, &v)
		v.rowAdditionalListofForwardingGTPTunnelEndpoint = new(s11.AdditionalListofForwardingGTPTunnelEndpoint)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEsValue: 1 synthetic rows")
}
func TestSelectedNRNeighbourInformationExtIEsValue(t *testing.T) {
	var absent *NRNeighbourInformationExtIEsValue
	selectedAssert(t, absent)
	v := NRNeighbourInformationExtIEsValue{}
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
	{
		v := NRNeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(380)
		selectedAssert(t, &v)
		v.rowCSIRSTransmissionIndication = new(s00.CSIRSTransmissionIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := NRNeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(389)
		selectedAssert(t, &v)
		v.rowSSBPositionsInBurst = new(s05.SSBPositionsInBurst)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := NRNeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(390)
		selectedAssert(t, &v)
		v.rowNRCellPRACHConfig = new(s00.NRCellPRACHConfig)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := NRNeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(433)
		selectedAssert(t, &v)
		v.rowAdditionalMeasurementTimingConfigurationList = new(s06.AdditionalMeasurementTimingConfigurationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union NRNeighbourInformationExtIEsValue: 4 synthetic rows")
}
func TestSelectedX2APMessageTransferIEValue(t *testing.T) {
	var absent *X2APMessageTransferIEValue
	selectedAssert(t, absent)
	v := X2APMessageTransferIEValue{}
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
	{
		v := X2APMessageTransferIEValue{}
		v.id = s00.ProtocolIEID(101)
		selectedAssert(t, &v)
		v.rowRNLHeader = new(s05.RNLHeader)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2APMessageTransferIEValue{}
		v.id = s00.ProtocolIEID(102)
		selectedAssert(t, &v)
		v.rowX2APMessage = new(X2APMessage)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2APMessageTransferIEValue: 2 synthetic rows")
}
func TestSelectedX2RemovalRequestIEValue(t *testing.T) {
	var absent *X2RemovalRequestIEValue
	selectedAssert(t, absent)
	v := X2RemovalRequestIEValue{}
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
	{
		v := X2RemovalRequestIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2RemovalRequestIEValue{}
		v.id = s00.ProtocolIEID(169)
		selectedAssert(t, &v)
		v.rowX2RemovalThreshold = new(X2BenefitValue)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2RemovalRequestIEValue: 2 synthetic rows")
}
