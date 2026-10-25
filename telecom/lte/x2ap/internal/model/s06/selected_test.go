// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s06

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
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
func TestSelectedCHOinformationREQExtIEsValue(t *testing.T) {
	var absent *CHOinformationREQExtIEsValue
	selectedAssert(t, absent)
	v := CHOinformationREQExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CHOinformationREQExtIEsValue{}
		v.id = s00.ProtocolIEID(446)
		selectedAssert(t, &v)
		v.rowCHOTimeBasedInformation = new(s01.CHOTimeBasedInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CHOinformationREQExtIEsValue: 1 synthetic rows")
}
func TestSelectedCellActivationFailureIEValue(t *testing.T) {
	var absent *CellActivationFailureIEValue
	selectedAssert(t, absent)
	v := CellActivationFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellActivationFailureIEValue: 2 synthetic rows")
}
func TestSelectedCellToReportEUTRAENDCItemIEValue(t *testing.T) {
	var absent *CellToReportEUTRAENDCItemIEValue
	selectedAssert(t, absent)
	v := CellToReportEUTRAENDCItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellToReportEUTRAENDCItemIEValue{}
		v.id = s00.ProtocolIEID(404)
		selectedAssert(t, &v)
		v.rowCellToReportEUTRAENDCItem = new(s04.CellToReportEUTRAENDCItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellToReportEUTRAENDCItemIEValue: 1 synthetic rows")
}
func TestSelectedCellToReportItemIEValue(t *testing.T) {
	var absent *CellToReportItemIEValue
	selectedAssert(t, absent)
	v := CellToReportItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellToReportItemIEValue{}
		v.id = s00.ProtocolIEID(31)
		selectedAssert(t, &v)
		v.rowCellToReportItem = new(s04.CellToReportItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellToReportItemIEValue: 1 synthetic rows")
}
func TestSelectedENBConfigurationUpdateAcknowledgeIEValue(t *testing.T) {
	var absent *ENBConfigurationUpdateAcknowledgeIEValue
	selectedAssert(t, absent)
	v := ENBConfigurationUpdateAcknowledgeIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENBConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBConfigurationUpdateAcknowledgeIEValue: 1 synthetic rows")
}
func TestSelectedENBConfigurationUpdateFailureIEValue(t *testing.T) {
	var absent *ENBConfigurationUpdateFailureIEValue
	selectedAssert(t, absent)
	v := ENBConfigurationUpdateFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENBConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(22)
		selectedAssert(t, &v)
		v.rowTimeToWait = new(s00.TimeToWait)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBConfigurationUpdateFailureIEValue: 3 synthetic rows")
}
func TestSelectedENBENDCX2RemovalReqAckIEValue(t *testing.T) {
	var absent *ENBENDCX2RemovalReqAckIEValue
	selectedAssert(t, absent)
	v := ENBENDCX2RemovalReqAckIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENBENDCX2RemovalReqAckIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBENDCX2RemovalReqAckIEValue: 1 synthetic rows")
}
func TestSelectedENBENDCX2RemovalReqIEValue(t *testing.T) {
	var absent *ENBENDCX2RemovalReqIEValue
	selectedAssert(t, absent)
	v := ENBENDCX2RemovalReqIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENBENDCX2RemovalReqIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBENDCX2RemovalReqIEValue: 1 synthetic rows")
}
func TestSelectedENDCCellActivationFailureIEValue(t *testing.T) {
	var absent *ENDCCellActivationFailureIEValue
	selectedAssert(t, absent)
	v := ENDCCellActivationFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCCellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(256)
		selectedAssert(t, &v)
		v.rowActivationID = new(s00.ActivationID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCCellActivationFailureIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCCellActivationFailureIEValue: 4 synthetic rows")
}
func TestSelectedENDCConfigurationTransferIEValue(t *testing.T) {
	var absent *ENDCConfigurationTransferIEValue
	selectedAssert(t, absent)
	v := ENDCConfigurationTransferIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCConfigurationTransferIEValue{}
		v.id = s00.ProtocolIEID(326)
		selectedAssert(t, &v)
		v.rowEndcSONConfigurationTransfer = new(s00.EndcSONConfigurationTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationTransferIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCConfigurationTransferIEValue: 2 synthetic rows")
}
func TestSelectedENDCConfigurationUpdateFailureIEValue(t *testing.T) {
	var absent *ENDCConfigurationUpdateFailureIEValue
	selectedAssert(t, absent)
	v := ENDCConfigurationUpdateFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(22)
		selectedAssert(t, &v)
		v.rowTimeToWait = new(s00.TimeToWait)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateFailureIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCConfigurationUpdateFailureIEValue: 4 synthetic rows")
}
func TestSelectedENDCResourceStatusFailureIEValue(t *testing.T) {
	var absent *ENDCResourceStatusFailureIEValue
	selectedAssert(t, absent)
	v := ENDCResourceStatusFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(383)
		selectedAssert(t, &v)
		v.rowEUTRANNode1MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(384)
		selectedAssert(t, &v)
		v.rowEUTRANNode2MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusFailureIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCResourceStatusFailureIEValue: 5 synthetic rows")
}
func TestSelectedENDCResourceStatusResponseIEValue(t *testing.T) {
	var absent *ENDCResourceStatusResponseIEValue
	selectedAssert(t, absent)
	v := ENDCResourceStatusResponseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(383)
		selectedAssert(t, &v)
		v.rowEUTRANNode1MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(384)
		selectedAssert(t, &v)
		v.rowEUTRANNode2MeasurementID = new(s00.MeasurementIDENDC)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCResourceStatusResponseIEValue: 4 synthetic rows")
}
func TestSelectedENDCX2RemovalFailureIEValue(t *testing.T) {
	var absent *ENDCX2RemovalFailureIEValue
	selectedAssert(t, absent)
	v := ENDCX2RemovalFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCX2RemovalFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2RemovalFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2RemovalFailureIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2RemovalFailureIEValue: 3 synthetic rows")
}
func TestSelectedENDCX2SetupFailureIEValue(t *testing.T) {
	var absent *ENDCX2SetupFailureIEValue
	selectedAssert(t, absent)
	v := ENDCX2SetupFailureIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ENDCX2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(22)
		selectedAssert(t, &v)
		v.rowTimeToWait = new(s00.TimeToWait)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupFailureIEValue{}
		v.id = s00.ProtocolIEID(350)
		selectedAssert(t, &v)
		v.rowMessageOversizeNotification = new(s05.MessageOversizeNotification)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2SetupFailureIEValue: 5 synthetic rows")
}
func TestSelectedERABItemIEValue(t *testing.T) {
	var absent *ERABItemIEValue
	selectedAssert(t, absent)
	v := ERABItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABItemIEValue{}
		v.id = s00.ProtocolIEID(2)
		selectedAssert(t, &v)
		v.rowERABItem = new(s04.ERABItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABItemIEValue: 1 synthetic rows")
}
func TestSelectedERABLevelQoSParametersExtIEsValue(t *testing.T) {
	var absent *ERABLevelQoSParametersExtIEsValue
	selectedAssert(t, absent)
	v := ERABLevelQoSParametersExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABLevelQoSParametersExtIEsValue{}
		v.id = s00.ProtocolIEID(273)
		selectedAssert(t, &v)
		v.rowDownlinkPacketLossRate = new(s00.PacketLossRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABLevelQoSParametersExtIEsValue{}
		v.id = s00.ProtocolIEID(274)
		selectedAssert(t, &v)
		v.rowUplinkPacketLossRate = new(s00.PacketLossRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABLevelQoSParametersExtIEsValue: 2 synthetic rows")
}
func TestSelectedERABUsageReportItemIEValue(t *testing.T) {
	var absent *ERABUsageReportItemIEValue
	selectedAssert(t, absent)
	v := ERABUsageReportItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABUsageReportItemIEValue{}
		v.id = s00.ProtocolIEID(263)
		selectedAssert(t, &v)
		v.rowERABUsageReportItem = new(s04.ERABUsageReportItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABUsageReportItemIEValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedItemExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedItemExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedItemExtIEsValue{}
		v.id = s00.ProtocolIEID(366)
		selectedAssert(t, &v)
		v.rowDAPSResponseInfo = new(s04.DAPSResponseInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedItemExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(314)
		selectedAssert(t, &v)
		v.rowLCID = new(s00.LCID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(314)
		selectedAssert(t, &v)
		v.rowLCID = new(s00.LCID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEsValue: 1 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEsValue: 2 synthetic rows")
}
func TestSelectedERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue(t *testing.T) {
	var absent *ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue
	selectedAssert(t, absent)
	v := ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(302)
		selectedAssert(t, &v)
		v.rowULpDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue{}
		v.id = s00.ProtocolIEID(311)
		selectedAssert(t, &v)
		v.rowDLPDCPSnLength = new(s00.PDCPSnLength)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEsValue: 2 synthetic rows")
}
