// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s09

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
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
func TestSelectedERABsAdmittedItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedItemIEValue{}
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
		v := ERABsAdmittedItemIEValue{}
		v.id = s00.ProtocolIEID(0)
		selectedAssert(t, &v)
		v.rowERABsAdmittedItem = new(ERABsAdmittedItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedItemSCGBearerExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedItemSCGBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedItemSplitBearerExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedItemSplitBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedItemSplitBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedModAckItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedModAckItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(436)
		selectedAssert(t, &v)
		v.rowSecurityResult = new(s05.SecurityResult)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEsValue: 4 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
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
		v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(436)
		selectedAssert(t, &v)
		v.rowSecurityResult = new(s05.SecurityResult)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEsValue: 4 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedModAckItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedModAckItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedModAckItemIEValue{}
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
		v := ERABsAdmittedToBeModifiedModAckItemIEValue{}
		v.id = s00.ProtocolIEID(132)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedModAckItem = new(ERABsAdmittedToBeModifiedModAckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedModAckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
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
		v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(312)
		selectedAssert(t, &v)
		v.rowSecondarysgNBDLGTPTEIDatPDCP = new(GTPtunnelEndpoint)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(300)
		selectedAssert(t, &v)
		v.rowRLCStatus = new(s05.RLCStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue: 2 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModConfItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModConfItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModConfItemIEValue{}
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
		v := ERABsAdmittedToBeModifiedSgNBModConfItemIEValue{}
		v.id = s00.ProtocolIEID(295)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedSgNBModConfItem = new(ERABsAdmittedToBeModifiedSgNBModConfItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModConfItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsDataForwardingAddressItemIEValue(t *testing.T) {
	var absent *ERABsDataForwardingAddressItemIEValue
	selectedAssert(t, absent)
	v := ERABsDataForwardingAddressItemIEValue{}
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
		v := ERABsDataForwardingAddressItemIEValue{}
		v.id = s00.ProtocolIEID(308)
		selectedAssert(t, &v)
		v.rowERABsDataForwardingAddressItem = new(ERABsDataForwardingAddressItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsDataForwardingAddressItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
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
		v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(166)
		selectedAssert(t, &v)
		v.rowCorrelationID = new(s00.CorrelationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(167)
		selectedAssert(t, &v)
		v.rowSIPTOCorrelationID = new(s00.CorrelationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(171)
		selectedAssert(t, &v)
		v.rowBearerType = new(s00.BearerType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedItemSCGBearerExtIEsValue: 5 synthetic rows")
}
func TestSelectedERABsToBeAddedItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedItemSplitBearerExtIEsValue{}
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
		v := ERABsToBeAddedItemSplitBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedItemSplitBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedModReqItemSCGBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedModReqItemSCGBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
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
		v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(166)
		selectedAssert(t, &v)
		v.rowCorrelationID = new(s00.CorrelationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(167)
		selectedAssert(t, &v)
		v.rowSIPTOCorrelationID = new(s00.CorrelationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(171)
		selectedAssert(t, &v)
		v.rowBearerType = new(s00.BearerType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedModReqItemSCGBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedModReqItemSCGBearerExtIEsValue: 5 synthetic rows")
}
func TestSelectedERABsToBeAddedModReqItemSplitBearerExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedModReqItemSplitBearerExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedModReqItemSplitBearerExtIEsValue{}
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
		v := ERABsToBeAddedModReqItemSplitBearerExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedModReqItemSplitBearerExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
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
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(317)
		selectedAssert(t, &v)
		v.rowRLCModeTransferred = new(s00.RLCMode)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(171)
		selectedAssert(t, &v)
		v.rowBearerType = new(s00.BearerType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(435)
		selectedAssert(t, &v)
		v.rowSecurityIndication = new(s05.SecurityIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(413)
		selectedAssert(t, &v)
		v.rowSourceNodeDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEsValue: 6 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
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
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(317)
		selectedAssert(t, &v)
		v.rowRLCModeTransferred = new(s00.RLCMode)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(171)
		selectedAssert(t, &v)
		v.rowBearerType = new(s00.BearerType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(435)
		selectedAssert(t, &v)
		v.rowSecurityIndication = new(s05.SecurityIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEsValue: 5 synthetic rows")
}
func TestSelectedERABsToBeModifiedModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeModifiedModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedModReqItemIEValue{}
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
		v := ERABsToBeModifiedModReqItemIEValue{}
		v.id = s00.ProtocolIEID(126)
		selectedAssert(t, &v)
		v.rowERABsToBeModifiedModReqItem = new(ERABsToBeModifiedModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
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
		v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(313)
		selectedAssert(t, &v)
		v.rowSecondarymeNBULGTPTEIDatPDCP = new(GTPtunnelEndpoint)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue: 3 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqdItemIEValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqdItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqdItemIEValue{}
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
		v := ERABsToBeModifiedSgNBModReqdItemIEValue{}
		v.id = s00.ProtocolIEID(228)
		selectedAssert(t, &v)
		v.rowERABsToBeModifiedSgNBModReqdItem = new(ERABsToBeModifiedSgNBModReqdItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqdItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeSetupItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeSetupItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeSetupItemExtIEsValue{}
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
		v := ERABsToBeSetupItemExtIEsValue{}
		v.id = s00.ProtocolIEID(171)
		selectedAssert(t, &v)
		v.rowBearerType = new(s00.BearerType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupItemExtIEsValue{}
		v.id = s00.ProtocolIEID(363)
		selectedAssert(t, &v)
		v.rowDAPSRequestInfo = new(s04.DAPSRequestInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupItemExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupItemExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupItemExtIEsValue{}
		v.id = s00.ProtocolIEID(435)
		selectedAssert(t, &v)
		v.rowSecurityIndication = new(s05.SecurityIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeSetupItemExtIEsValue: 5 synthetic rows")
}
