// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s11

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
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
func TestSelectedCPCCancelIEValue(t *testing.T) {
	var absent *CPCCancelIEValue
	selectedAssert(t, absent)
	v := CPCCancelIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CPCCancelIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CPCCancelIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CPCCancelIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CPCCancelIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CPCCancelIEValue{}
		v.id = s00.ProtocolIEID(239)
		selectedAssert(t, &v)
		v.rowTargetSgNBID = new(s05.GlobalGNBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CPCCancelIEValue: 5 synthetic rows")
}
func TestSelectedCellTrafficTraceIEValue(t *testing.T) {
	var absent *CellTrafficTraceIEValue
	selectedAssert(t, absent)
	v := CellTrafficTraceIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(333)
		selectedAssert(t, &v)
		v.rowEUTRANTraceID = new(s00.EUTRANTraceID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(377)
		selectedAssert(t, &v)
		v.rowTraceCollectionEntityIPAddress = new(s09.TraceCollectionEntityIPAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(376)
		selectedAssert(t, &v)
		v.rowPrivacyIndicator = new(s00.PrivacyIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellTrafficTraceIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellTrafficTraceIEValue: 6 synthetic rows")
}
func TestSelectedDeactivateTraceIEValue(t *testing.T) {
	var absent *DeactivateTraceIEValue
	selectedAssert(t, absent)
	v := DeactivateTraceIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := DeactivateTraceIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DeactivateTraceIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DeactivateTraceIEValue{}
		v.id = s00.ProtocolIEID(333)
		selectedAssert(t, &v)
		v.rowEUTRANTraceID = new(s00.EUTRANTraceID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DeactivateTraceIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union DeactivateTraceIEValue: 4 synthetic rows")
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
		v.rowERABsToBeAddedSgNBModReqItem = new(s10.ERABsToBeAddedSgNBModReqItem)
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
func TestSelectedERABsToBeSetupRetrieveItemIEValue(t *testing.T) {
	var absent *ERABsToBeSetupRetrieveItemIEValue
	selectedAssert(t, absent)
	v := ERABsToBeSetupRetrieveItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsToBeSetupRetrieveItemIEValue{}
		v.id = s00.ProtocolIEID(174)
		selectedAssert(t, &v)
		v.rowERABsToBeSetupRetrieveItem = new(ERABsToBeSetupRetrieveItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsToBeSetupRetrieveItemIEValue: 1 synthetic rows")
}
func TestSelectedEarlyStatusTransferIEValue(t *testing.T) {
	var absent *EarlyStatusTransferIEValue
	selectedAssert(t, absent)
	v := EarlyStatusTransferIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(367)
		selectedAssert(t, &v)
		v.rowProcedureStage = new(s06.ProcedureStageChoice)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EarlyStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EarlyStatusTransferIEValue: 6 synthetic rows")
}
func TestSelectedErrorIndicationIEValue(t *testing.T) {
	var absent *ErrorIndicationIEValue
	selectedAssert(t, absent)
	v := ErrorIndicationIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(264)
		selectedAssert(t, &v)
		v.rowOldSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ErrorIndicationIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ErrorIndicationIEValue: 8 synthetic rows")
}
func TestSelectedF1CTrafficTransferIEValue(t *testing.T) {
	var absent *F1CTrafficTransferIEValue
	selectedAssert(t, absent)
	v := F1CTrafficTransferIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := F1CTrafficTransferIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := F1CTrafficTransferIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := F1CTrafficTransferIEValue{}
		v.id = s00.ProtocolIEID(397)
		selectedAssert(t, &v)
		v.rowF1CTrafficContainer = new(s00.F1CTrafficContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := F1CTrafficTransferIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union F1CTrafficTransferIEValue: 4 synthetic rows")
}
func TestSelectedHandoverPreparationFailureIEValue(t *testing.T) {
	var absent *HandoverPreparationFailureIEValue
	selectedAssert(t, absent)
	v := HandoverPreparationFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := HandoverPreparationFailureIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverPreparationFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverPreparationFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverPreparationFailureIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverPreparationFailureIEValue{}
		v.id = s00.ProtocolIEID(364)
		selectedAssert(t, &v)
		v.rowRequestedTargetCellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverPreparationFailureIEValue: 5 synthetic rows")
}
func TestSelectedHandoverReportIEValue(t *testing.T) {
	var absent *HandoverReportIEValue
	selectedAssert(t, absent)
	v := HandoverReportIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(54)
		selectedAssert(t, &v)
		v.rowHandoverReportType = new(s00.HandoverReportType)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(52)
		selectedAssert(t, &v)
		v.rowSourceCellECGI = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(53)
		selectedAssert(t, &v)
		v.rowFailureCellECGI = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(49)
		selectedAssert(t, &v)
		v.rowReEstablishmentCellECGI = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(81)
		selectedAssert(t, &v)
		v.rowTargetCellInUTRAN = new(s09.TargetCellInUTRAN)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(83)
		selectedAssert(t, &v)
		v.rowSourceCellCRNTI = new(s00.CRNTI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(82)
		selectedAssert(t, &v)
		v.rowMobilityInformation = new(s00.MobilityInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(60)
		selectedAssert(t, &v)
		v.rowUERLFReportContainer = new(UERLFReportContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(107)
		selectedAssert(t, &v)
		v.rowUERLFReportContainerForExtendedBands = new(UERLFReportContainerForExtendedBands)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverReportIEValue{}
		v.id = s00.ProtocolIEID(382)
		selectedAssert(t, &v)
		v.rowTargetCellInNGRAN = new(s09.TargetCellInNGRAN)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverReportIEValue: 11 synthetic rows")
}
func TestSelectedHandoverSuccessIEValue(t *testing.T) {
	var absent *HandoverSuccessIEValue
	selectedAssert(t, absent)
	v := HandoverSuccessIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := HandoverSuccessIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverSuccessIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverSuccessIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverSuccessIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverSuccessIEValue{}
		v.id = s00.ProtocolIEID(11)
		selectedAssert(t, &v)
		v.rowTargetCellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverSuccessIEValue: 5 synthetic rows")
}
func TestSelectedRLFIndicationIEValue(t *testing.T) {
	var absent *RLFIndicationIEValue
	selectedAssert(t, absent)
	v := RLFIndicationIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(48)
		selectedAssert(t, &v)
		v.rowFailureCellPCI = new(s00.PCI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(49)
		selectedAssert(t, &v)
		v.rowReEstablishmentCellECGI = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(50)
		selectedAssert(t, &v)
		v.rowFailureCellCRNTI = new(s00.CRNTI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(51)
		selectedAssert(t, &v)
		v.rowShortMACI = new(s08.ShortMACI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(60)
		selectedAssert(t, &v)
		v.rowUERLFReportContainer = new(UERLFReportContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(75)
		selectedAssert(t, &v)
		v.rowRRCConnSetupIndicator = new(s00.RRCConnSetupIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(78)
		selectedAssert(t, &v)
		v.rowRRCConnReestabIndicator = new(s00.RRCConnReestabIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(107)
		selectedAssert(t, &v)
		v.rowUERLFReportContainerForExtendedBands = new(UERLFReportContainerForExtendedBands)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RLFIndicationIEValue{}
		v.id = s00.ProtocolIEID(374)
		selectedAssert(t, &v)
		v.rowNBIoTRLFReportContainer = new(s00.NBIoTRLFReportContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RLFIndicationIEValue: 9 synthetic rows")
}
func TestSelectedRRCTransferIEValue(t *testing.T) {
	var absent *RRCTransferIEValue
	selectedAssert(t, absent)
	v := RRCTransferIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(242)
		selectedAssert(t, &v)
		v.rowSplitSRB = new(s08.SplitSRB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(243)
		selectedAssert(t, &v)
		v.rowNRUeReport = new(s08.NRUeReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(342)
		selectedAssert(t, &v)
		v.rowFastMCGRecoverySNToMN = new(s08.FastMCGRecovery)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RRCTransferIEValue{}
		v.id = s00.ProtocolIEID(347)
		selectedAssert(t, &v)
		v.rowFastMCGRecoveryMNToSN = new(s08.FastMCGRecovery)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RRCTransferIEValue: 7 synthetic rows")
}
func TestSelectedRSRPMRListExtIEsValue(t *testing.T) {
	var absent *RSRPMRListExtIEsValue
	selectedAssert(t, absent)
	v := RSRPMRListExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RSRPMRListExtIEsValue{}
		v.id = s00.ProtocolIEID(147)
		selectedAssert(t, &v)
		v.rowUEID = new(UEID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RSRPMRListExtIEsValue: 1 synthetic rows")
}
func TestSelectedRetrieveUEContextFailureIEValue(t *testing.T) {
	var absent *RetrieveUEContextFailureIEValue
	selectedAssert(t, absent)
	v := RetrieveUEContextFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RetrieveUEContextFailureIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextFailureIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RetrieveUEContextFailureIEValue: 4 synthetic rows")
}
func TestSelectedRetrieveUEContextRequestIEValue(t *testing.T) {
	var absent *RetrieveUEContextRequestIEValue
	selectedAssert(t, absent)
	v := RetrieveUEContextRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(172)
		selectedAssert(t, &v)
		v.rowResumeID = new(s00.ResumeID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(51)
		selectedAssert(t, &v)
		v.rowShortMACI = new(s08.ShortMACI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(175)
		selectedAssert(t, &v)
		v.rowNewEUTRANCellIdentifier = new(s00.EUTRANCellIdentifier)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(50)
		selectedAssert(t, &v)
		v.rowFailureCellCRNTI = new(s00.CRNTI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextRequestIEValue{}
		v.id = s00.ProtocolIEID(48)
		selectedAssert(t, &v)
		v.rowFailureCellPCI = new(s00.PCI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RetrieveUEContextRequestIEValue: 7 synthetic rows")
}
func TestSelectedSCGFailureInformationReportIEValue(t *testing.T) {
	var absent *SCGFailureInformationReportIEValue
	selectedAssert(t, absent)
	v := SCGFailureInformationReportIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(450)
		selectedAssert(t, &v)
		v.rowSourcePSCellCGI = new(s05.NRCGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(451)
		selectedAssert(t, &v)
		v.rowFailedPSCellCGI = new(s05.NRCGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(452)
		selectedAssert(t, &v)
		v.rowSCGFailureReportContainer = new(s08.SCGFailureReportContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureInformationReportIEValue{}
		v.id = s00.ProtocolIEID(453)
		selectedAssert(t, &v)
		v.rowTimeSCGFailure = new(s09.TimeSCGFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SCGFailureInformationReportIEValue: 6 synthetic rows")
}
func TestSelectedSCGFailureTransferIEValue(t *testing.T) {
	var absent *SCGFailureTransferIEValue
	selectedAssert(t, absent)
	v := SCGFailureTransferIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SCGFailureTransferIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SCGFailureTransferIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SCGFailureTransferIEValue: 2 synthetic rows")
}
func TestSelectedUEContextInformationRetrieveExtIEsValue(t *testing.T) {
	var absent *UEContextInformationRetrieveExtIEsValue
	selectedAssert(t, absent)
	v := UEContextInformationRetrieveExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(184)
		selectedAssert(t, &v)
		v.rowUESidelinkAggregateMaximumBitRate = new(s06.UESidelinkAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(340)
		selectedAssert(t, &v)
		v.rowAdditionalRRMPriorityIndex = new(s00.AdditionalRRMPriorityIndex)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(360)
		selectedAssert(t, &v)
		v.rowEPCHandoverRestrictionListContainer = new(s00.EPCHandoverRestrictionListContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(371)
		selectedAssert(t, &v)
		v.rowNRUESidelinkAggregateMaximumBitRate = new(s05.NRUESidelinkAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(378)
		selectedAssert(t, &v)
		v.rowUERadioCapabilityID = new(UERadioCapabilityID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationRetrieveExtIEsValue{}
		v.id = s00.ProtocolIEID(408)
		selectedAssert(t, &v)
		v.rowIMSvoiceEPSfallbackfrom5G = new(s00.IMSvoiceEPSfallbackfrom5G)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEContextInformationRetrieveExtIEsValue: 6 synthetic rows")
}
func TestSelectedUERadioCapabilityIDMappingRequestIEValue(t *testing.T) {
	var absent *UERadioCapabilityIDMappingRequestIEValue
	selectedAssert(t, absent)
	v := UERadioCapabilityIDMappingRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UERadioCapabilityIDMappingRequestIEValue{}
		v.id = s00.ProtocolIEID(378)
		selectedAssert(t, &v)
		v.rowUERadioCapabilityID = new(UERadioCapabilityID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UERadioCapabilityIDMappingRequestIEValue: 1 synthetic rows")
}
func TestSelectedUERadioCapabilityIDMappingResponseIEValue(t *testing.T) {
	var absent *UERadioCapabilityIDMappingResponseIEValue
	selectedAssert(t, absent)
	v := UERadioCapabilityIDMappingResponseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UERadioCapabilityIDMappingResponseIEValue{}
		v.id = s00.ProtocolIEID(378)
		selectedAssert(t, &v)
		v.rowUERadioCapabilityID = new(UERadioCapabilityID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UERadioCapabilityIDMappingResponseIEValue{}
		v.id = s00.ProtocolIEID(400)
		selectedAssert(t, &v)
		v.rowUERadioCapability = new(UERadioCapability)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UERadioCapabilityIDMappingResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UERadioCapabilityIDMappingResponseIEValue: 3 synthetic rows")
}
