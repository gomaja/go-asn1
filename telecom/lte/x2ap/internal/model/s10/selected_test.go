// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s10

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
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
func TestSelectedERABsAdmittedToBeAddedItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedItemIEValue{}
		v.id = s00.ProtocolIEID(121)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedItem = new(ERABsAdmittedToBeAddedItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedModAckItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedModAckItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedModAckItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedModAckItemIEValue{}
		v.id = s00.ProtocolIEID(131)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedModAckItem = new(ERABsAdmittedToBeAddedModAckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedModAckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBAddReqAckItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBAddReqAckItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBAddReqAckItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemIEValue{}
		v.id = s00.ProtocolIEID(213)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedSgNBAddReqAckItem = new(ERABsAdmittedToBeAddedSgNBAddReqAckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBAddReqAckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBModAckItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBModAckItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBModAckItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedSgNBModAckItemIEValue{}
		v.id = s00.ProtocolIEID(222)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedSgNBModAckItem = new(ERABsAdmittedToBeAddedSgNBModAckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBModAckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModAckItemIEValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModAckItemIEValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModAckItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeModifiedSgNBModAckItemIEValue{}
		v.id = s00.ProtocolIEID(223)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedSgNBModAckItem = new(ERABsAdmittedToBeModifiedSgNBModAckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModAckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedItemIEValue(t *testing.T) {
	var absent *ERABsToBeAddedItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedItemIEValue{}
		v.id = s00.ProtocolIEID(118)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedItem = new(ERABsToBeAddedItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeAddedModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedModReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedModReqItemIEValue{}
		v.id = s00.ProtocolIEID(125)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedModReqItem = new(ERABsToBeAddedModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBAddReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBAddReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBAddReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedSgNBAddReqItemIEValue{}
		v.id = s00.ProtocolIEID(209)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedSgNBAddReqItem = new(ERABsToBeAddedSgNBAddReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBAddReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBModReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedSgNBModReqItemIEValue{}
		v.id = s00.ProtocolIEID(216)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedSgNBModReqItem = new(ERABsToBeAddedSgNBModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeModifiedSgNBModReqItemIEValue{}
		v.id = s00.ProtocolIEID(217)
		selectedAssert(t, &v)
		v.rowERABsToBeModifiedSgNBModReqItem = new(ERABsToBeModifiedSgNBModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedModReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedModReqItemIEValue{}
		v.id = s00.ProtocolIEID(127)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedModReqItem = new(ERABsToBeReleasedModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelConfItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelConfItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelConfItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedRelConfItemIEValue{}
		v.id = s00.ProtocolIEID(140)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedRelConfItem = new(ERABsToBeReleasedRelConfItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedRelConfItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedRelReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedRelReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedRelReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedRelReqItemIEValue{}
		v.id = s00.ProtocolIEID(138)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedRelReqItem = new(ERABsToBeReleasedRelReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedRelReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBModReqItemIEValue{}
		v.id = s00.ProtocolIEID(218)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBModReqItem = new(ERABsToBeReleasedSgNBModReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBModReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelConfItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelConfItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelConfItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBRelConfItemIEValue{}
		v.id = s00.ProtocolIEID(234)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelConfItem = new(ERABsToBeReleasedSgNBRelConfItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBRelConfItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBRelReqItemIEValue{}
		v.id = s00.ProtocolIEID(232)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelReqItem = new(ERABsToBeReleasedSgNBRelReqItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBRelReqItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeSetupItemIEValue(t *testing.T) {
	var absent *ERABsToBeSetupItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeSetupItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeSetupItemIEValue{}
		v.id = s00.ProtocolIEID(4)
		selectedAssert(t, &v)
		v.rowERABsToBeSetupItem = new(ERABsToBeSetupItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeSetupItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeSetupRetrieveItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeSetupRetrieveItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeSetupRetrieveItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeSetupRetrieveItemExtIEsValue{}
		v.id = s00.ProtocolIEID(185)
		selectedAssert(t, &v)
		v.rowULGTPtunnelEndpoint = new(s09.GTPtunnelEndpoint)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupRetrieveItemExtIEsValue{}
		v.id = s00.ProtocolIEID(306)
		selectedAssert(t, &v)
		v.rowDLForwarding = new(s00.DLForwarding)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupRetrieveItemExtIEsValue{}
		v.id = s00.ProtocolIEID(369)
		selectedAssert(t, &v)
		v.rowEthernetType = new(s00.EthernetType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupRetrieveItemExtIEsValue{}
		v.id = s00.ProtocolIEID(435)
		selectedAssert(t, &v)
		v.rowSecurityIndication = new(s05.SecurityIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeSetupRetrieveItemExtIEsValue{}
		v.id = s00.ProtocolIEID(412)
		selectedAssert(t, &v)
		v.rowSourceDLForwardingIPAddress = new(s09.TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeSetupRetrieveItemExtIEsValue: 5 synthetic rows")
}
