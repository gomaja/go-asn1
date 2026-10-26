// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s08

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
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
func TestSelectedCellToReportNRENDCItemIEValue(t *testing.T) {
	var absent *CellToReportNRENDCItemIEValue
	selectedAssert(t, absent)
	v := CellToReportNRENDCItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellToReportNRENDCItemIEValue{}
		v.id = s00.ProtocolIEID(392)
		selectedAssert(t, &v)
		v.rowCellToReportNRENDCItem = new(CellToReportNRENDCItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellToReportNRENDCItemIEValue: 1 synthetic rows")
}
func TestSelectedCompleteFailureCauseInformationItemIEValue(t *testing.T) {
	var absent *CompleteFailureCauseInformationItemIEValue
	selectedAssert(t, absent)
	v := CompleteFailureCauseInformationItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CompleteFailureCauseInformationItemIEValue{}
		v.id = s00.ProtocolIEID(69)
		selectedAssert(t, &v)
		v.rowCompleteFailureCauseInformationItem = new(CompleteFailureCauseInformationItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CompleteFailureCauseInformationItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsSubjectToStatusTransferItemExtIEsValue(t *testing.T) {
	var absent *ERABsSubjectToStatusTransferItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsSubjectToStatusTransferItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(91)
		selectedAssert(t, &v)
		v.rowReceiveStatusOfULPDCPSDUsExtended = new(ReceiveStatusOfULPDCPSDUsExtended)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(92)
		selectedAssert(t, &v)
		v.rowULCOUNTValueExtended = new(s01.COUNTValueExtended)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(93)
		selectedAssert(t, &v)
		v.rowDLCOUNTValueExtended = new(s01.COUNTValueExtended)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(150)
		selectedAssert(t, &v)
		v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 = new(ReceiveStatusOfULPDCPSDUsPDCPSNlength18)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(151)
		selectedAssert(t, &v)
		v.rowULCOUNTValuePDCPSNlength18 = new(s01.COUNTvaluePDCPSNlength18)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsSubjectToStatusTransferItemExtIEsValue{}
		v.id = s00.ProtocolIEID(152)
		selectedAssert(t, &v)
		v.rowDLCOUNTValuePDCPSNlength18 = new(s01.COUNTvaluePDCPSNlength18)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsSubjectToStatusTransferItemExtIEsValue: 6 synthetic rows")
}
func TestSelectedERABsSubjectToStatusTransferItemIEValue(t *testing.T) {
	var absent *ERABsSubjectToStatusTransferItemIEValue
	selectedAssert(t, absent)
	v := ERABsSubjectToStatusTransferItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsSubjectToStatusTransferItemIEValue{}
		v.id = s00.ProtocolIEID(19)
		selectedAssert(t, &v)
		v.rowERABsSubjectToStatusTransferItem = new(ERABsSubjectToStatusTransferItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsSubjectToStatusTransferItemIEValue: 1 synthetic rows")
}
func TestSelectedMeasurementFailureCauseItemIEValue(t *testing.T) {
	var absent *MeasurementFailureCauseItemIEValue
	selectedAssert(t, absent)
	v := MeasurementFailureCauseItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MeasurementFailureCauseItemIEValue{}
		v.id = s00.ProtocolIEID(67)
		selectedAssert(t, &v)
		v.rowMeasurementFailureCauseItem = new(MeasurementFailureCauseItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MeasurementFailureCauseItemIEValue: 1 synthetic rows")
}
func TestSelectedMeasurementInitiationResultItemIEValue(t *testing.T) {
	var absent *MeasurementInitiationResultItemIEValue
	selectedAssert(t, absent)
	v := MeasurementInitiationResultItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := MeasurementInitiationResultItemIEValue{}
		v.id = s00.ProtocolIEID(66)
		selectedAssert(t, &v)
		v.rowMeasurementInitiationResultItem = new(MeasurementInitiationResultItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MeasurementInitiationResultItemIEValue: 1 synthetic rows")
}
func TestSelectedNeighbourInformationExtIEsValue(t *testing.T) {
	var absent *NeighbourInformationExtIEsValue
	selectedAssert(t, absent)
	v := NeighbourInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := NeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(76)
		selectedAssert(t, &v)
		v.rowNeighbourTAC = new(TAC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := NeighbourInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(94)
		selectedAssert(t, &v)
		v.rowEARFCNExtension = new(s00.EARFCNExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union NeighbourInformationExtIEsValue: 2 synthetic rows")
}
func TestSelectedSecondaryRATUsageReportItemIEValue(t *testing.T) {
	var absent *SecondaryRATUsageReportItemIEValue
	selectedAssert(t, absent)
	v := SecondaryRATUsageReportItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SecondaryRATUsageReportItemIEValue{}
		v.id = s00.ProtocolIEID(266)
		selectedAssert(t, &v)
		v.rowSecondaryRATUsageReportItem = new(SecondaryRATUsageReportItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SecondaryRATUsageReportItemIEValue: 1 synthetic rows")
}
func TestSelectedUEContextInformationSgNBModReqExtIEsValue(t *testing.T) {
	var absent *UEContextInformationSgNBModReqExtIEsValue
	selectedAssert(t, absent)
	v := UEContextInformationSgNBModReqExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UEContextInformationSgNBModReqExtIEsValue{}
		v.id = s00.ProtocolIEID(275)
		selectedAssert(t, &v)
		v.rowSubscriberProfileIDforRFP = new(SubscriberProfileIDforRFP)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationSgNBModReqExtIEsValue{}
		v.id = s00.ProtocolIEID(340)
		selectedAssert(t, &v)
		v.rowAdditionalRRMPriorityIndex = new(s00.AdditionalRRMPriorityIndex)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationSgNBModReqExtIEsValue{}
		v.id = s00.ProtocolIEID(341)
		selectedAssert(t, &v)
		v.rowLowerLayerPresenceStatusChange = new(s00.LowerLayerPresenceStatusChange)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEContextInformationSgNBModReqExtIEsValue: 3 synthetic rows")
}
