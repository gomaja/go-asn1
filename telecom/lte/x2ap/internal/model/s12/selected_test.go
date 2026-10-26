// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s12

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
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
func TestSelectedCellInformationItemExtIEsValue(t *testing.T) {
	var absent *CellInformationItemExtIEsValue
	selectedAssert(t, absent)
	v := CellInformationItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(61)
		selectedAssert(t, &v)
		v.rowABSInformation = new(s00.ABSInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(62)
		selectedAssert(t, &v)
		v.rowInvokeIndication = new(s00.InvokeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(99)
		selectedAssert(t, &v)
		v.rowIntendedULDLConfiguration = new(s00.SubframeAssignment)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(100)
		selectedAssert(t, &v)
		v.rowExtendedULInterferenceOverloadInfo = new(ExtendedULInterferenceOverloadInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(108)
		selectedAssert(t, &v)
		v.rowCoMPInformation = new(s06.CoMPInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellInformationItemExtIEsValue{}
		v.id = s00.ProtocolIEID(106)
		selectedAssert(t, &v)
		v.rowDynamicDLTransmissionInformation = new(s04.DynamicDLTransmissionInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellInformationItemExtIEsValue: 6 synthetic rows")
}
func TestSelectedCellInformationItemIEValue(t *testing.T) {
	var absent *CellInformationItemIEValue
	selectedAssert(t, absent)
	v := CellInformationItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellInformationItemIEValue{}
		v.id = s00.ProtocolIEID(7)
		selectedAssert(t, &v)
		v.rowCellInformationItem = new(CellInformationItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellInformationItemIEValue: 1 synthetic rows")
}
func TestSelectedCellMeasurementResultEUTRAENDCItemIEValue(t *testing.T) {
	var absent *CellMeasurementResultEUTRAENDCItemIEValue
	selectedAssert(t, absent)
	v := CellMeasurementResultEUTRAENDCItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellMeasurementResultEUTRAENDCItemIEValue{}
		v.id = s00.ProtocolIEID(402)
		selectedAssert(t, &v)
		v.rowCellMeasurementResultEUTRAENDCItem = new(CellMeasurementResultEUTRAENDCItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellMeasurementResultEUTRAENDCItemIEValue: 1 synthetic rows")
}
func TestSelectedCellMeasurementResultNRENDCItemIEValue(t *testing.T) {
	var absent *CellMeasurementResultNRENDCItemIEValue
	selectedAssert(t, absent)
	v := CellMeasurementResultNRENDCItemIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := CellMeasurementResultNRENDCItemIEValue{}
		v.id = s00.ProtocolIEID(394)
		selectedAssert(t, &v)
		v.rowCellMeasurementResultNRENDCItem = new(CellMeasurementResultNRENDCItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellMeasurementResultNRENDCItemIEValue: 1 synthetic rows")
}
func TestSelectedNRRadioResourceStatusExtIEsValue(t *testing.T) {
	var absent *NRRadioResourceStatusExtIEsValue
	selectedAssert(t, absent)
	v := NRRadioResourceStatusExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := NRRadioResourceStatusExtIEsValue{}
		v.id = s00.ProtocolIEID(439)
		selectedAssert(t, &v)
		v.rowMIMOPRBusageInformation = new(MIMOPRBusageInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union NRRadioResourceStatusExtIEsValue: 1 synthetic rows")
}
func TestSelectedRadioResourceStatusExtIEsValue(t *testing.T) {
	var absent *RadioResourceStatusExtIEsValue
	selectedAssert(t, absent)
	v := RadioResourceStatusExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := RadioResourceStatusExtIEsValue{}
		v.id = s00.ProtocolIEID(193)
		selectedAssert(t, &v)
		v.rowDLSchedulingPDCCHCCEUsage = new(s00.DLSchedulingPDCCHCCEUsage)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RadioResourceStatusExtIEsValue{}
		v.id = s00.ProtocolIEID(194)
		selectedAssert(t, &v)
		v.rowULSchedulingPDCCHCCEUsage = new(ULSchedulingPDCCHCCEUsage)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RadioResourceStatusExtIEsValue: 2 synthetic rows")
}
func TestSelectedSeNBModificationRequestIEValue(t *testing.T) {
	var absent *SeNBModificationRequestIEValue
	selectedAssert(t, absent)
	v := SeNBModificationRequestIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(136)
		selectedAssert(t, &v)
		v.rowSCGChangeIndication = new(s00.SCGChangeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(116)
		selectedAssert(t, &v)
		v.rowServingPLMN = new(s00.PLMNIdentity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(124)
		selectedAssert(t, &v)
		v.rowUEContextInformationSeNBModReq = new(s11.UEContextInformationSeNBModReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(119)
		selectedAssert(t, &v)
		v.rowMeNBtoSeNBContainer = new(s00.MeNBtoSeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(71)
		selectedAssert(t, &v)
		v.rowCSGMembershipStatus = new(s00.CSGMembershipStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBModificationRequestIEValue: 10 synthetic rows")
}
func TestSelectedSeNBModificationRequestRejectIEValue(t *testing.T) {
	var absent *SeNBModificationRequestRejectIEValue
	selectedAssert(t, absent)
	v := SeNBModificationRequestRejectIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBModificationRequestRejectIEValue: 6 synthetic rows")
}
func TestSelectedSeNBReconfigurationCompleteIEValue(t *testing.T) {
	var absent *SeNBReconfigurationCompleteIEValue
	selectedAssert(t, absent)
	v := SeNBReconfigurationCompleteIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SeNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(123)
		selectedAssert(t, &v)
		v.rowResponseInformationSeNBReconfComp = new(s05.ResponseInformationSeNBReconfComp)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBReconfigurationCompleteIEValue: 5 synthetic rows")
}
func TestSelectedSeNBReleaseRequiredIEValue(t *testing.T) {
	var absent *SeNBReleaseRequiredIEValue
	selectedAssert(t, absent)
	v := SeNBReleaseRequiredIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SeNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBReleaseRequiredIEValue: 5 synthetic rows")
}
func TestSelectedSgNBAdditionRequestRejectIEValue(t *testing.T) {
	var absent *SgNBAdditionRequestRejectIEValue
	selectedAssert(t, absent)
	v := SgNBAdditionRequestRejectIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBAdditionRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBAdditionRequestRejectIEValue: 5 synthetic rows")
}
func TestSelectedSgNBChangeRefuseIEValue(t *testing.T) {
	var absent *SgNBChangeRefuseIEValue
	selectedAssert(t, absent)
	v := SgNBChangeRefuseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBChangeRefuseIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRefuseIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRefuseIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRefuseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRefuseIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBChangeRefuseIEValue: 5 synthetic rows")
}
func TestSelectedSgNBModificationRefuseIEValue(t *testing.T) {
	var absent *SgNBModificationRefuseIEValue
	selectedAssert(t, absent)
	v := SgNBModificationRefuseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRefuseIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationRefuseIEValue: 6 synthetic rows")
}
func TestSelectedSgNBModificationRequestRejectIEValue(t *testing.T) {
	var absent *SgNBModificationRequestRejectIEValue
	selectedAssert(t, absent)
	v := SgNBModificationRequestRejectIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationRequestRejectIEValue: 5 synthetic rows")
}
func TestSelectedSgNBReconfigurationCompleteIEValue(t *testing.T) {
	var absent *SgNBReconfigurationCompleteIEValue
	selectedAssert(t, absent)
	v := SgNBReconfigurationCompleteIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(214)
		selectedAssert(t, &v)
		v.rowResponseInformationSgNBReconfComp = new(s05.ResponseInformationSgNBReconfComp)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReconfigurationCompleteIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReconfigurationCompleteIEValue: 4 synthetic rows")
}
func TestSelectedSgNBReleaseRequestRejectIEValue(t *testing.T) {
	var absent *SgNBReleaseRequestRejectIEValue
	selectedAssert(t, absent)
	v := SgNBReleaseRequestRejectIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := SgNBReleaseRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestRejectIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReleaseRequestRejectIEValue: 5 synthetic rows")
}
func TestSelectedUEContextReleaseIEValue(t *testing.T) {
	var absent *UEContextReleaseIEValue
	selectedAssert(t, absent)
	v := UEContextReleaseIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
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
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(164)
		selectedAssert(t, &v)
		v.rowSIPTOBearerDeactivationIndication = new(s00.SIPTOBearerDeactivationIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextReleaseIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEContextReleaseIEValue: 6 synthetic rows")
}
