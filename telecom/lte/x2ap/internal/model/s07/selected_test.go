// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s07

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
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
func TestSelectedENDCX2RemovalRequestIEValue(t *testing.T) {
	var absent *ENDCX2RemovalRequestIEValue
	selectedAssert(t, absent)
	v := ENDCX2RemovalRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCX2RemovalRequestIEValue{}
		v.id = s00.ProtocolIEID(298)
		selectedAssert(t, &v)
		v.rowInitiatingNodeTypeEndcX2Removal = new(InitiatingNodeTypeEndcX2Removal)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2RemovalRequestIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2RemovalRequestIEValue: 2 synthetic rows")
}
func TestSelectedENDCX2RemovalResponseIEValue(t *testing.T) {
	var absent *ENDCX2RemovalResponseIEValue
	selectedAssert(t, absent)
	v := ENDCX2RemovalResponseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCX2RemovalResponseIEValue{}
		v.id = s00.ProtocolIEID(299)
		selectedAssert(t, &v)
		v.rowRespondingNodeTypeEndcX2Removal = new(RespondingNodeTypeEndcX2Removal)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2RemovalResponseIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2RemovalResponseIEValue: 2 synthetic rows")
}
func TestSelectedERABsSubjectToSgNBCounterCheckItemIEValue(t *testing.T) {
	var absent *ERABsSubjectToSgNBCounterCheckItemIEValue
	selectedAssert(t, absent)
	v := ERABsSubjectToSgNBCounterCheckItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsSubjectToSgNBCounterCheckItemIEValue{}
		v.id = s00.ProtocolIEID(236)
		selectedAssert(t, &v)
		v.rowERABsSubjectToSgNBCounterCheckItem = new(s05.ERABsSubjectToSgNBCounterCheckItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsSubjectToSgNBCounterCheckItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(315)
		selectedAssert(t, &v)
		v.rowDuplicationActivation = new(s00.DuplicationActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEsValue: 3 synthetic rows")
}
func TestSelectedERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(315)
		selectedAssert(t, &v)
		v.rowDuplicationActivation = new(s00.DuplicationActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEsValue: 3 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(300)
		selectedAssert(t, &v)
		v.rowRLCStatus = new(s05.RLCStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(300)
		selectedAssert(t, &v)
		v.rowRLCStatus = new(s05.RLCStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(314)
		selectedAssert(t, &v)
		v.rowLCID = new(s00.LCID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEsValue: 2 synthetic rows")
}
func TestSelectedERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(325)
		selectedAssert(t, &v)
		v.rowNewDrbIDReq = new(s00.NewDRBIDrequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEsValue: 3 synthetic rows")
}
func TestSelectedERABsToBeReleasedModReqdItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedModReqdItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedModReqdItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedModReqdItemIEValue{}
		v.id = s00.ProtocolIEID(135)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedModReqdItem = new(s05.ERABsToBeReleasedModReqdItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedModReqdItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqdItemExtIEsValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqdItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqdItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBModReqdItemExtIEsValue{}
		v.id = s00.ProtocolIEID(317)
		selectedAssert(t, &v)
		v.rowRLCModeTransferred = new(s00.RLCMode)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBModReqdItemExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBModReqdItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBModReqdItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBModReqdItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBModReqdItemIEValue{}
		v.id = s00.ProtocolIEID(227)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBModReqdItem = new(ERABsToBeReleasedSgNBModReqdItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBModReqdItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsToBeReleasedSgNBRelReqdItemIEValue(t *testing.T) {
	var absent *ERABsToBeReleasedSgNBRelReqdItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeReleasedSgNBRelReqdItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeReleasedSgNBRelReqdItemIEValue{}
		v.id = s00.ProtocolIEID(321)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelReqdItem = new(s05.ERABsToBeReleasedSgNBRelReqdItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeReleasedSgNBRelReqdItemIEValue: 1 synthetic rows")
}
func TestSelectedEnGNBENDCX2RemovalReqAckIEValue(t *testing.T) {
	var absent *EnGNBENDCX2RemovalReqAckIEValue
	selectedAssert(t, absent)
	v := EnGNBENDCX2RemovalReqAckIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := EnGNBENDCX2RemovalReqAckIEValue{}
		v.id = s00.ProtocolIEID(252)
		selectedAssert(t, &v)
		v.rowGlobalenGNBID = new(s05.GlobalGNBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EnGNBENDCX2RemovalReqAckIEValue: 1 synthetic rows")
}
func TestSelectedEnGNBENDCX2RemovalReqIEValue(t *testing.T) {
	var absent *EnGNBENDCX2RemovalReqIEValue
	selectedAssert(t, absent)
	v := EnGNBENDCX2RemovalReqIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := EnGNBENDCX2RemovalReqIEValue{}
		v.id = s00.ProtocolIEID(252)
		selectedAssert(t, &v)
		v.rowGlobalenGNBID = new(s05.GlobalGNBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EnGNBENDCX2RemovalReqIEValue: 1 synthetic rows")
}
func TestSelectedFDDInfoExtIEsValue(t *testing.T) {
	var absent *FDDInfoExtIEsValue
	selectedAssert(t, absent)
	v := FDDInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(95)
		selectedAssert(t, &v)
		v.rowULEARFCNExtension = new(s00.EARFCNExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(96)
		selectedAssert(t, &v)
		v.rowDLEARFCNExtension = new(s00.EARFCNExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(177)
		selectedAssert(t, &v)
		v.rowOffsetOfNbiotChannelNumberToDLEARFCN = new(s00.OffsetOfNbiotChannelNumberToEARFCN)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(178)
		selectedAssert(t, &v)
		v.rowOffsetOfNbiotChannelNumberToULEARFCN = new(s00.OffsetOfNbiotChannelNumberToEARFCN)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(282)
		selectedAssert(t, &v)
		v.rowNRSNSSSPowerOffset = new(s00.NRSNSSSPowerOffset)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(283)
		selectedAssert(t, &v)
		v.rowNSSSNumOccasionDifferentPrecoder = new(s00.NSSSNumOccasionDifferentPrecoder)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union FDDInfoExtIEsValue: 6 synthetic rows")
}
func TestSelectedGBRQosInformationExtIEsValue(t *testing.T) {
	var absent *GBRQosInformationExtIEsValue
	selectedAssert(t, absent)
	v := GBRQosInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := GBRQosInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(196)
		selectedAssert(t, &v)
		v.rowExtendedERABMaximumBitrateDL = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := GBRQosInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(197)
		selectedAssert(t, &v)
		v.rowExtendedERABMaximumBitrateUL = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := GBRQosInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(198)
		selectedAssert(t, &v)
		v.rowExtendedERABGuaranteedBitrateDL = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := GBRQosInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(199)
		selectedAssert(t, &v)
		v.rowExtendedERABGuaranteedBitrateUL = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union GBRQosInformationExtIEsValue: 4 synthetic rows")
}
func TestSelectedGNBStatusIndicationIEValue(t *testing.T) {
	var absent *GNBStatusIndicationIEValue
	selectedAssert(t, absent)
	v := GNBStatusIndicationIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := GNBStatusIndicationIEValue{}
		v.id = s00.ProtocolIEID(310)
		selectedAssert(t, &v)
		v.rowGNBOverloadInformation = new(s00.GNBOverloadInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := GNBStatusIndicationIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union GNBStatusIndicationIEValue: 2 synthetic rows")
}
func TestSelectedGTPtunnelEndpointExtIEsValue(t *testing.T) {
	var absent *GTPtunnelEndpointExtIEsValue
	selectedAssert(t, absent)
	v := GTPtunnelEndpointExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := GTPtunnelEndpointExtIEsValue{}
		v.id = s00.ProtocolIEID(396)
		selectedAssert(t, &v)
		v.rowQoSMappingInformation = new(s05.QoSMappingInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union GTPtunnelEndpointExtIEsValue: 1 synthetic rows")
}
func TestSelectedLocationReportingInformationExtIEsValue(t *testing.T) {
	var absent *LocationReportingInformationExtIEsValue
	selectedAssert(t, absent)
	v := LocationReportingInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := LocationReportingInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(409)
		selectedAssert(t, &v)
		v.rowAdditionLocationInformation = new(s00.AdditionLocationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union LocationReportingInformationExtIEsValue: 1 synthetic rows")
}
func TestSelectedM4ConfigurationExtIEsValue(t *testing.T) {
	var absent *M4ConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := M4ConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := M4ConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(442)
		selectedAssert(t, &v)
		v.rowM4ReportAmount = new(s00.M4ReportAmountMDT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union M4ConfigurationExtIEsValue: 1 synthetic rows")
}
func TestSelectedM5ConfigurationExtIEsValue(t *testing.T) {
	var absent *M5ConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := M5ConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := M5ConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(443)
		selectedAssert(t, &v)
		v.rowM5ReportAmount = new(s00.M5ReportAmountMDT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union M5ConfigurationExtIEsValue: 1 synthetic rows")
}
func TestSelectedM6ConfigurationExtIEsValue(t *testing.T) {
	var absent *M6ConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := M6ConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := M6ConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(444)
		selectedAssert(t, &v)
		v.rowM6ReportAmount = new(s00.M6ReportAmountMDT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union M6ConfigurationExtIEsValue: 1 synthetic rows")
}
func TestSelectedM7ConfigurationExtIEsValue(t *testing.T) {
	var absent *M7ConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := M7ConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := M7ConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(445)
		selectedAssert(t, &v)
		v.rowM7ReportAmount = new(s00.M7ReportAmountMDT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union M7ConfigurationExtIEsValue: 1 synthetic rows")
}
func TestSelectedMeNBResourceCoordinationInformationExtIEsValue(t *testing.T) {
	var absent *MeNBResourceCoordinationInformationExtIEsValue
	selectedAssert(t, absent)
	v := MeNBResourceCoordinationInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MeNBResourceCoordinationInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(322)
		selectedAssert(t, &v)
		v.rowNRCGI = new(s05.NRCGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MeNBResourceCoordinationInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(323)
		selectedAssert(t, &v)
		v.rowMeNBCoordinationAssistanceInformation = new(s00.MeNBCoordinationAssistanceInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MeNBResourceCoordinationInformationExtIEsValue: 2 synthetic rows")
}
func TestSelectedMobilityChangeAcknowledgeIEValue(t *testing.T) {
	var absent *MobilityChangeAcknowledgeIEValue
	selectedAssert(t, absent)
	v := MobilityChangeAcknowledgeIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MobilityChangeAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(43)
		selectedAssert(t, &v)
		v.rowENB1CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(44)
		selectedAssert(t, &v)
		v.rowENB2CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MobilityChangeAcknowledgeIEValue: 3 synthetic rows")
}
func TestSelectedMobilityChangeFailureIEValue(t *testing.T) {
	var absent *MobilityChangeFailureIEValue
	selectedAssert(t, absent)
	v := MobilityChangeFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MobilityChangeFailureIEValue{}
		v.id = s00.ProtocolIEID(43)
		selectedAssert(t, &v)
		v.rowENB1CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeFailureIEValue{}
		v.id = s00.ProtocolIEID(44)
		selectedAssert(t, &v)
		v.rowENB2CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeFailureIEValue{}
		v.id = s00.ProtocolIEID(47)
		selectedAssert(t, &v)
		v.rowENB2MobilityParametersModificationRange = new(s00.MobilityParametersModificationRange)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MobilityChangeFailureIEValue: 5 synthetic rows")
}
func TestSelectedMobilityChangeRequestIEValue(t *testing.T) {
	var absent *MobilityChangeRequestIEValue
	selectedAssert(t, absent)
	v := MobilityChangeRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MobilityChangeRequestIEValue{}
		v.id = s00.ProtocolIEID(43)
		selectedAssert(t, &v)
		v.rowENB1CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeRequestIEValue{}
		v.id = s00.ProtocolIEID(44)
		selectedAssert(t, &v)
		v.rowENB2CellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeRequestIEValue{}
		v.id = s00.ProtocolIEID(46)
		selectedAssert(t, &v)
		v.rowENB1MobilityParameters = new(s00.MobilityParametersInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeRequestIEValue{}
		v.id = s00.ProtocolIEID(45)
		selectedAssert(t, &v)
		v.rowENB2ProposedMobilityParameters = new(s00.MobilityParametersInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MobilityChangeRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MobilityChangeRequestIEValue: 5 synthetic rows")
}
func TestSelectedNRFreqInfoExtIEsValue(t *testing.T) {
	var absent *NRFreqInfoExtIEsValue
	selectedAssert(t, absent)
	v := NRFreqInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := NRFreqInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(388)
		selectedAssert(t, &v)
		v.rowFrequencyShift7p5khz = new(s00.FrequencyShift7p5khz)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union NRFreqInfoExtIEsValue: 1 synthetic rows")
}
func TestSelectedNRRAReportListItemExtIEsValue(t *testing.T) {
	var absent *NRRAReportListItemExtIEsValue
	selectedAssert(t, absent)
	v := NRRAReportListItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := NRRAReportListItemExtIEsValue{}
		v.id = s00.ProtocolIEID(448)
		selectedAssert(t, &v)
		v.rowPSCellListContainer = new(s00.PSCellListContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union NRRAReportListItemExtIEsValue: 1 synthetic rows")
}
func TestSelectedProSeAuthorizedExtIEsValue(t *testing.T) {
	var absent *ProSeAuthorizedExtIEsValue
	selectedAssert(t, absent)
	v := ProSeAuthorizedExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ProSeAuthorizedExtIEsValue{}
		v.id = s00.ProtocolIEID(149)
		selectedAssert(t, &v)
		v.rowProSeUEtoNetworkRelaying = new(s00.ProSeUEtoNetworkRelaying)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ProSeAuthorizedExtIEsValue: 1 synthetic rows")
}
func TestSelectedRelativeNarrowbandTxPowerExtIEsValue(t *testing.T) {
	var absent *RelativeNarrowbandTxPowerExtIEsValue
	selectedAssert(t, absent)
	v := RelativeNarrowbandTxPowerExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RelativeNarrowbandTxPowerExtIEsValue{}
		v.id = s00.ProtocolIEID(148)
		selectedAssert(t, &v)
		v.rowEnhancedRNTP = new(s05.EnhancedRNTP)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RelativeNarrowbandTxPowerExtIEsValue: 1 synthetic rows")
}
func TestSelectedResetRequestIEValue(t *testing.T) {
	var absent *ResetRequestIEValue
	selectedAssert(t, absent)
	v := ResetRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ResetRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResetRequestIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResetRequestIEValue: 2 synthetic rows")
}
func TestSelectedResetResponseIEValue(t *testing.T) {
	var absent *ResetResponseIEValue
	selectedAssert(t, absent)
	v := ResetResponseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ResetResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResetResponseIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResetResponseIEValue: 2 synthetic rows")
}
func TestSelectedSgNBResourceCoordinationInformationExtIEsValue(t *testing.T) {
	var absent *SgNBResourceCoordinationInformationExtIEsValue
	selectedAssert(t, absent)
	v := SgNBResourceCoordinationInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBResourceCoordinationInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(316)
		selectedAssert(t, &v)
		v.rowECGI = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBResourceCoordinationInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(324)
		selectedAssert(t, &v)
		v.rowSgNBCoordinationAssistanceInformation = new(s00.SgNBCoordinationAssistanceInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBResourceCoordinationInformationExtIEsValue: 2 synthetic rows")
}
func TestSelectedTDDInfoExtIEsValue(t *testing.T) {
	var absent *TDDInfoExtIEsValue
	selectedAssert(t, absent)
	v := TDDInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := TDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(97)
		selectedAssert(t, &v)
		v.rowAdditionalSpecialSubframeInfo = new(s01.AdditionalSpecialSubframeInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(94)
		selectedAssert(t, &v)
		v.rowEARFCNExtension = new(s00.EARFCNExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(179)
		selectedAssert(t, &v)
		v.rowAdditionalSpecialSubframeExtensionInfo = new(s01.AdditionalSpecialSubframeExtensionInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(177)
		selectedAssert(t, &v)
		v.rowOffsetOfNbiotChannelNumberToDLEARFCN = new(s00.OffsetOfNbiotChannelNumberToEARFCN)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoExtIEsValue{}
		v.id = s00.ProtocolIEID(338)
		selectedAssert(t, &v)
		v.rowNBIoTULDLAlignmentOffset = new(s00.NBIoTULDLAlignmentOffset)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union TDDInfoExtIEsValue: 5 synthetic rows")
}
func TestSelectedUEAggregateMaximumBitrateExtIEsValue(t *testing.T) {
	var absent *UEAggregateMaximumBitrateExtIEsValue
	selectedAssert(t, absent)
	v := UEAggregateMaximumBitrateExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UEAggregateMaximumBitrateExtIEsValue{}
		v.id = s00.ProtocolIEID(200)
		selectedAssert(t, &v)
		v.rowExtendedUEaggregateMaximumBitRateDownlink = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEAggregateMaximumBitrateExtIEsValue{}
		v.id = s00.ProtocolIEID(201)
		selectedAssert(t, &v)
		v.rowExtendedUEaggregateMaximumBitRateUplink = new(s00.ExtendedBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEAggregateMaximumBitrateExtIEsValue: 2 synthetic rows")
}
func TestSelectedUEAppLayerMeasConfigExtIEsValue(t *testing.T) {
	var absent *UEAppLayerMeasConfigExtIEsValue
	selectedAssert(t, absent)
	v := UEAppLayerMeasConfigExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UEAppLayerMeasConfigExtIEsValue{}
		v.id = s00.ProtocolIEID(276)
		selectedAssert(t, &v)
		v.rowServiceType = new(s00.ServiceType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEAppLayerMeasConfigExtIEsValue: 1 synthetic rows")
}
func TestSelectedX2ReleaseIEValue(t *testing.T) {
	var absent *X2ReleaseIEValue
	selectedAssert(t, absent)
	v := X2ReleaseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := X2ReleaseIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2ReleaseIEValue: 1 synthetic rows")
}
func TestSelectedX2RemovalFailureIEValue(t *testing.T) {
	var absent *X2RemovalFailureIEValue
	selectedAssert(t, absent)
	v := X2RemovalFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := X2RemovalFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2RemovalFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2RemovalFailureIEValue: 2 synthetic rows")
}
func TestSelectedX2RemovalResponseIEValue(t *testing.T) {
	var absent *X2RemovalResponseIEValue
	selectedAssert(t, absent)
	v := X2RemovalResponseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := X2RemovalResponseIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2RemovalResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2RemovalResponseIEValue: 2 synthetic rows")
}
func TestSelectedX2SetupFailureIEValue(t *testing.T) {
	var absent *X2SetupFailureIEValue
	selectedAssert(t, absent)
	v := X2SetupFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := X2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(22)
		selectedAssert(t, &v)
		v.rowTimeToWait = new(s00.TimeToWait)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2SetupFailureIEValue: 3 synthetic rows")
}
