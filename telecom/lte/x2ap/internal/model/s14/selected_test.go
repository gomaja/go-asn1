// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s14

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
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
func TestSelectedConditionalHandoverCancelIEValue(t *testing.T) {
	var absent *ConditionalHandoverCancelIEValue
	selectedAssert(t, absent)
	v := ConditionalHandoverCancelIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ConditionalHandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(365)
		selectedAssert(t, &v)
		v.rowCandidateCellsToBeCancelledList = new(s06.CandidateCellsToBeCancelledList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ConditionalHandoverCancelIEValue: 6 synthetic rows")
}
func TestSelectedENDCResourceStatusRequestIEValue(t *testing.T) {
	var absent *ENDCResourceStatusRequestIEValue
	selectedAssert(t, absent)
	v := ENDCResourceStatusRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(383)
		selectedAssert(t, &v)
		v.rowEUTRANNode1MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(384)
		selectedAssert(t, &v)
		v.rowEUTRANNode2MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(28)
		selectedAssert(t, &v)
		v.rowRegistrationRequest = new(s00.RegistrationRequestENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(30)
		selectedAssert(t, &v)
		v.rowReportingPeriodicity = new(s00.ReportingPeriodicityENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(38)
		selectedAssert(t, &v)
		v.rowReportCharacteristics = new(s08.ReportCharacteristicsENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(391)
		selectedAssert(t, &v)
		v.rowCellToReportNRENDC = new(s08.CellToReportNRENDCList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(403)
		selectedAssert(t, &v)
		v.rowCellToReportEUTRAENDC = new(s08.CellToReportEUTRAENDCList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCResourceStatusRequestIEValue: 8 synthetic rows")
}
func TestSelectedENDCResourceStatusUpdateIEValue(t *testing.T) {
	var absent *ENDCResourceStatusUpdateIEValue
	selectedAssert(t, absent)
	v := ENDCResourceStatusUpdateIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(383)
		selectedAssert(t, &v)
		v.rowEUTRANNode1MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(384)
		selectedAssert(t, &v)
		v.rowEUTRANNode2MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(393)
		selectedAssert(t, &v)
		v.rowCellMeasurementResultNRENDC = new(s12.CellMeasurementResultNRENDCList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(401)
		selectedAssert(t, &v)
		v.rowCellMeasurementResultEUTRAENDC = new(s12.CellMeasurementResultEUTRAENDCList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCResourceStatusUpdateIEValue: 5 synthetic rows")
}
func TestSelectedHandoverCancelIEValue(t *testing.T) {
	var absent *HandoverCancelIEValue
	selectedAssert(t, absent)
	v := HandoverCancelIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverCancelIEValue{}
		v.id = s00.ProtocolIEID(365)
		selectedAssert(t, &v)
		v.rowCandidateCellsToBeCancelledList = new(s06.CandidateCellsToBeCancelledList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverCancelIEValue: 6 synthetic rows")
}
func TestSelectedHandoverRequestAcknowledgeIEValue(t *testing.T) {
	var absent *HandoverRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := HandoverRequestAcknowledgeIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(1)
		selectedAssert(t, &v)
		v.rowERABsAdmittedList = new(s11.ERABsAdmittedList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(3)
		selectedAssert(t, &v)
		v.rowERABsNotAdmittedList = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(12)
		selectedAssert(t, &v)
		v.rowTargeteNBtoSourceENBTransparentContainer = new(s09.TargeteNBtoSourceENBTransparentContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(154)
		selectedAssert(t, &v)
		v.rowUEContextKeptIndicator = new(s00.UEContextKeptIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(183)
		selectedAssert(t, &v)
		v.rowWTUEContextKeptIndicator = new(s00.UEContextKeptIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(339)
		selectedAssert(t, &v)
		v.rowERABsTransferredToMeNB = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(362)
		selectedAssert(t, &v)
		v.rowCHOinformationACK = new(s04.CHOinformationACK)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverRequestAcknowledgeIEValue: 13 synthetic rows")
}
func TestSelectedLoadInformationIEValue(t *testing.T) {
	var absent *LoadInformationIEValue
	selectedAssert(t, absent)
	v := LoadInformationIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := LoadInformationIEValue{}
		v.id = s00.ProtocolIEID(6)
		selectedAssert(t, &v)
		v.rowCellInformation = new(s12.CellInformationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union LoadInformationIEValue: 1 synthetic rows")
}
func TestSelectedResourceStatusFailureIEValue(t *testing.T) {
	var absent *ResourceStatusFailureIEValue
	selectedAssert(t, absent)
	v := ResourceStatusFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(39)
		selectedAssert(t, &v)
		v.rowENB1MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(40)
		selectedAssert(t, &v)
		v.rowENB2MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(68)
		selectedAssert(t, &v)
		v.rowCompleteFailureCauseInformationList = new(s08.CompleteFailureCauseInformationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResourceStatusFailureIEValue: 5 synthetic rows")
}
func TestSelectedResourceStatusRequestIEValue(t *testing.T) {
	var absent *ResourceStatusRequestIEValue
	selectedAssert(t, absent)
	v := ResourceStatusRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(39)
		selectedAssert(t, &v)
		v.rowENB1MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(40)
		selectedAssert(t, &v)
		v.rowENB2MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(28)
		selectedAssert(t, &v)
		v.rowRegistrationRequest = new(s00.RegistrationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(38)
		selectedAssert(t, &v)
		v.rowReportCharacteristics = new(s08.ReportCharacteristics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(29)
		selectedAssert(t, &v)
		v.rowCellToReport = new(s08.CellToReportList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(30)
		selectedAssert(t, &v)
		v.rowReportingPeriodicity = new(s00.ReportingPeriodicity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(64)
		selectedAssert(t, &v)
		v.rowPartialSuccessIndicator = new(s00.PartialSuccessIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(109)
		selectedAssert(t, &v)
		v.rowReportingPeriodicityRSRPMR = new(s00.ReportingPeriodicityRSRPMR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusRequestIEValue{}
		v.id = s00.ProtocolIEID(145)
		selectedAssert(t, &v)
		v.rowReportingPeriodicityCSIR = new(s00.ReportingPeriodicityCSIR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResourceStatusRequestIEValue: 9 synthetic rows")
}
func TestSelectedSeNBAdditionRequestAcknowledgeIEValue(t *testing.T) {
	var absent *SeNBAdditionRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := SeNBAdditionRequestAcknowledgeIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(120)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedList = new(s11.ERABsAdmittedToBeAddedList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(3)
		selectedAssert(t, &v)
		v.rowERABsNotAdmittedList = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(122)
		selectedAssert(t, &v)
		v.rowSeNBtoMeNBContainer = new(s08.SeNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(165)
		selectedAssert(t, &v)
		v.rowGWTransportLayerAddress = new(s09.TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(168)
		selectedAssert(t, &v)
		v.rowSIPTOLGWTransportLayerAddress = new(s09.TransportLayerAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(163)
		selectedAssert(t, &v)
		v.rowTunnelInformationForBBF = new(s10.TunnelInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBAdditionRequestAcknowledgeIEValue: 11 synthetic rows")
}
func TestSelectedServedNRCellInformationExtIEsValue(t *testing.T) {
	var absent *ServedNRCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := ServedNRCellInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(334)
		selectedAssert(t, &v)
		v.rowAdditionalPLMNsItem = new(s00.AdditionalPLMNsItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(337)
		selectedAssert(t, &v)
		v.rowBPLMNIDInfoNR = new(s06.BPLMNIDInfoNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(389)
		selectedAssert(t, &v)
		v.rowSSBPositionsInBurst = new(s05.SSBPositionsInBurst)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(390)
		selectedAssert(t, &v)
		v.rowNRCellPRACHConfig = new(s00.NRCellPRACHConfig)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(380)
		selectedAssert(t, &v)
		v.rowCSIRSTransmissionIndication = new(s00.CSIRSTransmissionIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(406)
		selectedAssert(t, &v)
		v.rowSFNOffset = new(s05.SFNOffset)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(433)
		selectedAssert(t, &v)
		v.rowAdditionalMeasurementTimingConfigurationList = new(s06.AdditionalMeasurementTimingConfigurationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ServedNRCellInformationExtIEsValue: 7 synthetic rows")
}
func TestSelectedSgNBActivityNotificationIEValue(t *testing.T) {
	var absent *SgNBActivityNotificationIEValue
	selectedAssert(t, absent)
	v := SgNBActivityNotificationIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBActivityNotificationIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBActivityNotificationIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBActivityNotificationIEValue{}
		v.id = s00.ProtocolIEID(296)
		selectedAssert(t, &v)
		v.rowUEContextLevelUserPlaneActivity = new(s00.UserPlaneTrafficActivityReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBActivityNotificationIEValue{}
		v.id = s00.ProtocolIEID(297)
		selectedAssert(t, &v)
		v.rowERABActivityNotifyItemList = new(s06.ERABActivityNotifyItemList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBActivityNotificationIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBActivityNotificationIEValue: 5 synthetic rows")
}
func TestSelectedSgNBAdditionRequestAcknowledgeIEValue(t *testing.T) {
	var absent *SgNBAdditionRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := SgNBAdditionRequestAcknowledgeIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(210)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedSgNBAddReqAckList = new(s11.ERABsAdmittedToBeAddedSgNBAddReqAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(3)
		selectedAssert(t, &v)
		v.rowERABsNotAdmittedList = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(211)
		selectedAssert(t, &v)
		v.rowSgNBtoMeNBContainer = new(s08.SgNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(212)
		selectedAssert(t, &v)
		v.rowAdmittedSplitSRBs = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(258)
		selectedAssert(t, &v)
		v.rowSgNBResourceCoordinationInformation = new(s08.SgNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(272)
		selectedAssert(t, &v)
		v.rowRRCConfigIndication = new(s00.RRCConfigInd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(331)
		selectedAssert(t, &v)
		v.rowLocationInformationSgNB = new(s05.LocationInformationSgNB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(344)
		selectedAssert(t, &v)
		v.rowAvailableFastMCGRecoveryViaSRB3 = new(s00.AvailableFastMCGRecoveryViaSRB3)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(410)
		selectedAssert(t, &v)
		v.rowDirectForwardingPathAvailability = new(s00.DirectForwardingPathAvailability)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(422)
		selectedAssert(t, &v)
		v.rowSCGActivationStatus = new(s00.SCGActivationStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(425)
		selectedAssert(t, &v)
		v.rowCPAinformationREQACK = new(s06.CPAinformationREQACK)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBAdditionRequestAcknowledgeIEValue: 15 synthetic rows")
}
func TestSelectedUnsuccessfulValue(t *testing.T) {
	var absent *UnsuccessfulValue
	selectedAssert(t, absent)
	v := UnsuccessfulValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(0)
		selectedAssert(t, &v)
		v.bodyHandoverPreparationFailure = new(HandoverPreparationFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(6)
		selectedAssert(t, &v)
		v.bodyX2SetupFailure = new(X2SetupFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(8)
		selectedAssert(t, &v)
		v.bodyENBConfigurationUpdateFailure = new(ENBConfigurationUpdateFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(9)
		selectedAssert(t, &v)
		v.bodyResourceStatusFailure = new(ResourceStatusFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(12)
		selectedAssert(t, &v)
		v.bodyMobilityChangeFailure = new(MobilityChangeFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(15)
		selectedAssert(t, &v)
		v.bodyCellActivationFailure = new(CellActivationFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(18)
		selectedAssert(t, &v)
		v.bodyX2RemovalFailure = new(X2RemovalFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(19)
		selectedAssert(t, &v)
		v.bodySeNBAdditionRequestReject = new(SeNBAdditionRequestReject)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(21)
		selectedAssert(t, &v)
		v.bodySeNBModificationRequestReject = new(SeNBModificationRequestReject)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(22)
		selectedAssert(t, &v)
		v.bodySeNBModificationRefuse = new(SeNBModificationRefuse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(26)
		selectedAssert(t, &v)
		v.bodyRetrieveUEContextFailure = new(RetrieveUEContextFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(27)
		selectedAssert(t, &v)
		v.bodySgNBAdditionRequestReject = new(SgNBAdditionRequestReject)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(29)
		selectedAssert(t, &v)
		v.bodySgNBModificationRequestReject = new(SgNBModificationRequestReject)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(30)
		selectedAssert(t, &v)
		v.bodySgNBModificationRefuse = new(SgNBModificationRefuse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(31)
		selectedAssert(t, &v)
		v.bodySgNBReleaseRequestReject = new(SgNBReleaseRequestReject)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(34)
		selectedAssert(t, &v)
		v.bodySgNBChangeRefuse = new(SgNBChangeRefuse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(36)
		selectedAssert(t, &v)
		v.bodyENDCX2SetupFailure = new(ENDCX2SetupFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(37)
		selectedAssert(t, &v)
		v.bodyENDCConfigurationUpdateFailure = new(ENDCConfigurationUpdateFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(39)
		selectedAssert(t, &v)
		v.bodyENDCCellActivationFailure = new(ENDCCellActivationFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(43)
		selectedAssert(t, &v)
		v.bodyENDCX2RemovalFailure = new(ENDCX2RemovalFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UnsuccessfulValue{}
		v.code = s00.ProcedureCode(54)
		selectedAssert(t, &v)
		v.bodyENDCResourceStatusFailure = new(ENDCResourceStatusFailure)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UnsuccessfulValue: 21 synthetic rows")
}
