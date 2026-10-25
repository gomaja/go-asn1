// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s17

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
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
func TestSelectedCellActivationRequestIEValue(t *testing.T) {
	var absent *CellActivationRequestIEValue
	selectedAssert(t, absent)
	v := CellActivationRequestIEValue{}
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
		v := CellActivationRequestIEValue{}
		v.id = s00.ProtocolIEID(57)
		selectedAssert(t, &v)
		v.rowServedCellsToActivate = new(s08.ServedCellsToActivate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellActivationRequestIEValue: 1 synthetic rows")
}
func TestSelectedCellMeasurementResultItemExtIEsValue(t *testing.T) {
	var absent *CellMeasurementResultItemExtIEsValue
	selectedAssert(t, absent)
	v := CellMeasurementResultItemExtIEsValue{}
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
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(42)
		selectedAssert(t, &v)
		v.rowCompositeAvailableCapacityGroup = new(s04.CompositeAvailableCapacityGroup)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(63)
		selectedAssert(t, &v)
		v.rowABSStatus = new(s06.ABSStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(110)
		selectedAssert(t, &v)
		v.rowRSRPMRList = new(s11.RSRPMRList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(146)
		selectedAssert(t, &v)
		v.rowCSIReportList = new(s11.CSIReportList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(170)
		selectedAssert(t, &v)
		v.rowCellReportingIndicator = new(s00.CellReportingIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := CellMeasurementResultItemExtIEsValue{}
		v.id = s00.ProtocolIEID(417)
		selectedAssert(t, &v)
		v.rowMeasurementResultforNRCellsPossiblyAggregated = new(s08.MeasurementResultforNRCellsPossiblyAggregated)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellMeasurementResultItemExtIEsValue: 6 synthetic rows")
}
func TestSelectedCellMeasurementResultItemIEValue(t *testing.T) {
	var absent *CellMeasurementResultItemIEValue
	selectedAssert(t, absent)
	v := CellMeasurementResultItemIEValue{}
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
		v := CellMeasurementResultItemIEValue{}
		v.id = s00.ProtocolIEID(33)
		selectedAssert(t, &v)
		v.rowCellMeasurementResultItem = new(CellMeasurementResultItem)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union CellMeasurementResultItemIEValue: 1 synthetic rows")
}
func TestSelectedENBConfigurationUpdateIEValue(t *testing.T) {
	var absent *ENBConfigurationUpdateIEValue
	selectedAssert(t, absent)
	v := ENBConfigurationUpdateIEValue{}
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
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(25)
		selectedAssert(t, &v)
		v.rowServedCellsToAdd = new(ServedCells)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(26)
		selectedAssert(t, &v)
		v.rowServedCellsToModify = new(s16.ServedCellsToModify)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(27)
		selectedAssert(t, &v)
		v.rowServedCellsToDelete = new(s08.OldECGIs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(34)
		selectedAssert(t, &v)
		v.rowGUGroupIDToAddList = new(s08.GUGroupIDList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(35)
		selectedAssert(t, &v)
		v.rowGUGroupIDToDeleteList = new(s08.GUGroupIDList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(143)
		selectedAssert(t, &v)
		v.rowCoverageModificationList = new(s08.CoverageModificationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBConfigurationUpdateIEValue: 6 synthetic rows")
}
func TestSelectedENBENDCConfigUpdateIEValue(t *testing.T) {
	var absent *ENBENDCConfigUpdateIEValue
	selectedAssert(t, absent)
	v := ENBENDCConfigUpdateIEValue{}
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
		v := ENBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(251)
		selectedAssert(t, &v)
		v.rowCellAssistanceInformation = new(s08.CellAssistanceInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(250)
		selectedAssert(t, &v)
		v.rowServedEUTRAcellsENDCX2ManagementList = new(s16.ServedEUTRAcellsENDCX2ManagementList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(259)
		selectedAssert(t, &v)
		v.rowServedEUTRAcellsToModifyListENDCConfUpd = new(s16.ServedEUTRAcellsToModifyListENDCConfUpd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(260)
		selectedAssert(t, &v)
		v.rowServedEUTRAcellsToDeleteListENDCConfUpd = new(s08.ServedEUTRAcellsToDeleteListENDCConfUpd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBENDCConfigUpdateIEValue: 4 synthetic rows")
}
func TestSelectedENBENDCX2SetupReqAckIEValue(t *testing.T) {
	var absent *ENBENDCX2SetupReqAckIEValue
	selectedAssert(t, absent)
	v := ENBENDCX2SetupReqAckIEValue{}
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
		v := ENBENDCX2SetupReqAckIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqAckIEValue{}
		v.id = s00.ProtocolIEID(250)
		selectedAssert(t, &v)
		v.rowServedEUTRAcellsENDCX2ManagementList = new(s16.ServedEUTRAcellsENDCX2ManagementList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqAckIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqAckIEValue{}
		v.id = s00.ProtocolIEID(351)
		selectedAssert(t, &v)
		v.rowCellandCapacityAssistInfo = new(s08.CellandCapacityAssistInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBENDCX2SetupReqAckIEValue: 4 synthetic rows")
}
func TestSelectedENBENDCX2SetupReqIEValue(t *testing.T) {
	var absent *ENBENDCX2SetupReqIEValue
	selectedAssert(t, absent)
	v := ENBENDCX2SetupReqIEValue{}
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
		v := ENBENDCX2SetupReqIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqIEValue{}
		v.id = s00.ProtocolIEID(250)
		selectedAssert(t, &v)
		v.rowServedEUTRAcellsENDCX2ManagementList = new(s16.ServedEUTRAcellsENDCX2ManagementList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBENDCX2SetupReqIEValue{}
		v.id = s00.ProtocolIEID(351)
		selectedAssert(t, &v)
		v.rowCellandCapacityAssistInfo = new(s08.CellandCapacityAssistInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBENDCX2SetupReqIEValue: 4 synthetic rows")
}
func TestSelectedEnGNBServedCellsExtIEsValue(t *testing.T) {
	var absent *EnGNBServedCellsExtIEsValue
	selectedAssert(t, absent)
	v := EnGNBServedCellsExtIEsValue{}
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
		v := EnGNBServedCellsExtIEsValue{}
		v.id = s00.ProtocolIEID(434)
		selectedAssert(t, &v)
		v.rowServedCellSpecificInfoReqNR = new(s08.ServedCellSpecificInfoReqNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EnGNBServedCellsExtIEsValue: 1 synthetic rows")
}
func TestSelectedRachIndicationIEValue(t *testing.T) {
	var absent *RachIndicationIEValue
	selectedAssert(t, absent)
	v := RachIndicationIEValue{}
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
		v := RachIndicationIEValue{}
		v.id = s00.ProtocolIEID(447)
		selectedAssert(t, &v)
		v.rowRaReportIndicationList = new(s12.RaReportIndicationList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RachIndicationIEValue: 1 synthetic rows")
}
func TestSelectedResourceStatusUpdateIEValue(t *testing.T) {
	var absent *ResourceStatusUpdateIEValue
	selectedAssert(t, absent)
	v := ResourceStatusUpdateIEValue{}
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
		v := ResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(39)
		selectedAssert(t, &v)
		v.rowENB1MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(40)
		selectedAssert(t, &v)
		v.rowENB2MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusUpdateIEValue{}
		v.id = s00.ProtocolIEID(32)
		selectedAssert(t, &v)
		v.rowCellMeasurementResult = new(CellMeasurementResultList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResourceStatusUpdateIEValue: 3 synthetic rows")
}
func TestSelectedRetrieveUEContextResponseIEValue(t *testing.T) {
	var absent *RetrieveUEContextResponseIEValue
	selectedAssert(t, absent)
	v := RetrieveUEContextResponseIEValue{}
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
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(23)
		selectedAssert(t, &v)
		v.rowGUMMEIID = new(s05.GUMMEI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(173)
		selectedAssert(t, &v)
		v.rowUEContextInformationRetrieve = new(UEContextInformationRetrieve)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(13)
		selectedAssert(t, &v)
		v.rowTraceActivation = new(s16.TraceActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(36)
		selectedAssert(t, &v)
		v.rowSRVCCOperationPossible = new(s00.SRVCCOperationPossible)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(98)
		selectedAssert(t, &v)
		v.rowMaskedIMEISV = new(s00.MaskedIMEISV)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(104)
		selectedAssert(t, &v)
		v.rowExpectedUEBehaviour = new(s05.ExpectedUEBehaviour)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(103)
		selectedAssert(t, &v)
		v.rowProSeAuthorized = new(s08.ProSeAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(176)
		selectedAssert(t, &v)
		v.rowV2XServicesAuthorized = new(s06.V2XServicesAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(277)
		selectedAssert(t, &v)
		v.rowAerialUEsubscriptionInformation = new(s00.AerialUEsubscriptionInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(309)
		selectedAssert(t, &v)
		v.rowSubscriptionBasedUEDifferentiationInfo = new(s05.SubscriptionBasedUEDifferentiationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(370)
		selectedAssert(t, &v)
		v.rowNRV2XServicesAuthorized = new(s05.NRV2XServicesAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := RetrieveUEContextResponseIEValue{}
		v.id = s00.ProtocolIEID(372)
		selectedAssert(t, &v)
		v.rowPC5QoSParameters = new(s08.PC5QoSParameters)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union RetrieveUEContextResponseIEValue: 17 synthetic rows")
}
func TestSelectedSecondaryRATDataUsageReportIEValue(t *testing.T) {
	var absent *SecondaryRATDataUsageReportIEValue
	selectedAssert(t, absent)
	v := SecondaryRATDataUsageReportIEValue{}
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
		v := SecondaryRATDataUsageReportIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SecondaryRATDataUsageReportIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SecondaryRATDataUsageReportIEValue{}
		v.id = s00.ProtocolIEID(265)
		selectedAssert(t, &v)
		v.rowSecondaryRATUsageReportList = new(s08.SecondaryRATUsageReportList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SecondaryRATDataUsageReportIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SecondaryRATDataUsageReportIEValue: 4 synthetic rows")
}
func TestSelectedServedCellExtIEsValue(t *testing.T) {
	var absent *ServedCellExtIEsValue
	selectedAssert(t, absent)
	v := ServedCellExtIEsValue{}
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
		v := ServedCellExtIEsValue{}
		v.id = s00.ProtocolIEID(327)
		selectedAssert(t, &v)
		v.rowNRNeighbourInfoToAdd = new(s16.NRNeighbourInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellExtIEsValue{}
		v.id = s00.ProtocolIEID(434)
		selectedAssert(t, &v)
		v.rowServedCellSpecificInfoReqNR = new(s08.ServedCellSpecificInfoReqNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ServedCellExtIEsValue: 2 synthetic rows")
}
func TestSelectedSgNBChangeRequiredIEValue(t *testing.T) {
	var absent *SgNBChangeRequiredIEValue
	selectedAssert(t, absent)
	v := SgNBChangeRequiredIEValue{}
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
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(239)
		selectedAssert(t, &v)
		v.rowTargetSgNBID = new(s05.GlobalGNBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(211)
		selectedAssert(t, &v)
		v.rowSgNBtoMeNBContainer = new(s08.SgNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(415)
		selectedAssert(t, &v)
		v.rowSCGUEHistoryInformation = new(s08.SCGUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeRequiredIEValue{}
		v.id = s00.ProtocolIEID(429)
		selectedAssert(t, &v)
		v.rowCPCinformationREQD = new(s08.CPCinformationREQD)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBChangeRequiredIEValue: 8 synthetic rows")
}
func TestSelectedSgNBModificationRequestAcknowledgeIEValue(t *testing.T) {
	var absent *SgNBModificationRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := SgNBModificationRequestAcknowledgeIEValue{}
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
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(219)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedSgNBModAckList = new(s11.ERABsAdmittedToBeAddedSgNBModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(220)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedSgNBModAckList = new(s11.ERABsAdmittedToBeModifiedSgNBModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(221)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeReleasedSgNBModAckList = new(s08.ERABsAdmittedToBeReleasedSgNBModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(3)
		selectedAssert(t, &v)
		v.rowERABsNotAdmittedList = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(211)
		selectedAssert(t, &v)
		v.rowSgNBtoMeNBContainer = new(s08.SgNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(258)
		selectedAssert(t, &v)
		v.rowSgNBResourceCoordinationInformation = new(s08.SgNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(212)
		selectedAssert(t, &v)
		v.rowAdmittedSplitSRBs = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(281)
		selectedAssert(t, &v)
		v.rowAdmittedSplitSRBsrelease = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(272)
		selectedAssert(t, &v)
		v.rowRRCConfigIndication = new(s00.RRCConfigInd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(331)
		selectedAssert(t, &v)
		v.rowLocationInformationSgNB = new(s05.LocationInformationSgNB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(344)
		selectedAssert(t, &v)
		v.rowAvailableFastMCGRecoveryViaSRB3 = new(s00.AvailableFastMCGRecoveryViaSRB3)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(346)
		selectedAssert(t, &v)
		v.rowReleaseFastMCGRecoveryViaSRB3 = new(s00.ReleaseFastMCGRecoveryViaSRB3)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(415)
		selectedAssert(t, &v)
		v.rowSCGUEHistoryInformation = new(s08.SCGUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(422)
		selectedAssert(t, &v)
		v.rowSCGActivationStatus = new(s00.SCGActivationStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(427)
		selectedAssert(t, &v)
		v.rowCPAinformationMODACK = new(s06.CPAinformationMODACK)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationRequestAcknowledgeIEValue: 19 synthetic rows")
}
func TestSelectedSgNBModificationRequestIEValue(t *testing.T) {
	var absent *SgNBModificationRequestIEValue
	selectedAssert(t, absent)
	v := SgNBModificationRequestIEValue{}
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
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(269)
		selectedAssert(t, &v)
		v.rowSelectedPLMN = new(s00.PLMNIdentity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(240)
		selectedAssert(t, &v)
		v.rowHandoverRestrictionList = new(s16.HandoverRestrictionList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(241)
		selectedAssert(t, &v)
		v.rowSCGConfigurationQuery = new(s00.SCGConfigurationQuery)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(215)
		selectedAssert(t, &v)
		v.rowUEContextInformationSgNBModReq = new(s11.UEContextInformationSgNBModReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(257)
		selectedAssert(t, &v)
		v.rowMeNBResourceCoordinationInformation = new(s08.MeNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(208)
		selectedAssert(t, &v)
		v.rowRequestedSplitSRBs = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(280)
		selectedAssert(t, &v)
		v.rowRequestedSplitSRBsrelease = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(329)
		selectedAssert(t, &v)
		v.rowDesiredActNotificationLevel = new(s00.DesiredActNotificationLevel)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(330)
		selectedAssert(t, &v)
		v.rowLocationInformationSgNBReporting = new(s00.LocationInformationSgNBReporting)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(279)
		selectedAssert(t, &v)
		v.rowMeNBCellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(343)
		selectedAssert(t, &v)
		v.rowRequestedFastMCGRecoveryViaSRB3 = new(s00.RequestedFastMCGRecoveryViaSRB3)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(345)
		selectedAssert(t, &v)
		v.rowRequestedFastMCGRecoveryViaSRB3Release = new(s00.RequestedFastMCGRecoveryViaSRB3Release)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(379)
		selectedAssert(t, &v)
		v.rowSNtriggered = new(s00.SNtriggered)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(395)
		selectedAssert(t, &v)
		v.rowIABNodeIndication = new(s00.IABNodeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(416)
		selectedAssert(t, &v)
		v.rowPSCellHistoryInformationRetrieve = new(s00.PSCellHistoryInformationRetrieve)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(105)
		selectedAssert(t, &v)
		v.rowUEHistoryInformationFromTheUE = new(s11.UEHistoryInformationFromTheUE)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(421)
		selectedAssert(t, &v)
		v.rowCHOinformationModReq = new(s01.CHOinformationModReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(423)
		selectedAssert(t, &v)
		v.rowSCGActivationRequest = new(s00.SCGActivationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(426)
		selectedAssert(t, &v)
		v.rowCPAinformationMOD = new(s01.CPAinformationMOD)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(432)
		selectedAssert(t, &v)
		v.rowCPCupdateMOD = new(s06.CPCupdateMOD)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequestIEValue{}
		v.id = s00.ProtocolIEID(449)
		selectedAssert(t, &v)
		v.rowIABAuthorized = new(s00.IABAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationRequestIEValue: 26 synthetic rows")
}
func TestSelectedSgNBModificationRequiredIEValue(t *testing.T) {
	var absent *SgNBModificationRequiredIEValue
	selectedAssert(t, absent)
	v := SgNBModificationRequiredIEValue{}
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
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(249)
		selectedAssert(t, &v)
		v.rowPDCPChangeIndication = new(s00.PDCPChangeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(225)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBModReqdList = new(s08.ERABsToBeReleasedSgNBModReqdList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(211)
		selectedAssert(t, &v)
		v.rowSgNBtoMeNBContainer = new(s08.SgNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(226)
		selectedAssert(t, &v)
		v.rowERABsToBeModifiedSgNBModReqdList = new(s11.ERABsToBeModifiedSgNBModReqdList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(258)
		selectedAssert(t, &v)
		v.rowSgNBResourceCoordinationInformation = new(s08.SgNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(272)
		selectedAssert(t, &v)
		v.rowRRCConfigIndication = new(s00.RRCConfigInd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(331)
		selectedAssert(t, &v)
		v.rowLocationInformationSgNB = new(s05.LocationInformationSgNB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(415)
		selectedAssert(t, &v)
		v.rowSCGUEHistoryInformation = new(s08.SCGUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(423)
		selectedAssert(t, &v)
		v.rowSCGActivationRequest = new(s00.SCGActivationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(428)
		selectedAssert(t, &v)
		v.rowCPACinformationREQD = new(s06.CPACinformationREQD)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(438)
		selectedAssert(t, &v)
		v.rowSCGreconfigNotification = new(s00.SCGreconfigNotification)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationRequiredIEValue: 15 synthetic rows")
}
func TestSelectedSgNBReleaseRequestAcknowledgeIEValue(t *testing.T) {
	var absent *SgNBReleaseRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := SgNBReleaseRequestAcknowledgeIEValue{}
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
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(318)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeReleasedSgNBRelReqAckList = new(s08.ERABsAdmittedToBeReleasedSgNBRelReqAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(415)
		selectedAssert(t, &v)
		v.rowSCGUEHistoryInformation = new(s08.SCGUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReleaseRequestAcknowledgeIEValue: 6 synthetic rows")
}
func TestSelectedSgNBReleaseRequiredIEValue(t *testing.T) {
	var absent *SgNBReleaseRequiredIEValue
	selectedAssert(t, absent)
	v := SgNBReleaseRequiredIEValue{}
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
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(320)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelReqdList = new(s08.ERABsToBeReleasedSgNBRelReqdList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(211)
		selectedAssert(t, &v)
		v.rowSgNBtoMeNBContainer = new(s08.SgNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequiredIEValue{}
		v.id = s00.ProtocolIEID(415)
		selectedAssert(t, &v)
		v.rowSCGUEHistoryInformation = new(s08.SCGUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReleaseRequiredIEValue: 7 synthetic rows")
}
func TestSelectedX2SetupRequestIEValue(t *testing.T) {
	var absent *X2SetupRequestIEValue
	selectedAssert(t, absent)
	v := X2SetupRequestIEValue{}
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
		v := X2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(20)
		selectedAssert(t, &v)
		v.rowServedCells = new(ServedCells)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(24)
		selectedAssert(t, &v)
		v.rowGUGroupIDList = new(s08.GUGroupIDList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(159)
		selectedAssert(t, &v)
		v.rowLHNID = new(s00.LHNID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2SetupRequestIEValue: 4 synthetic rows")
}
func TestSelectedX2SetupResponseIEValue(t *testing.T) {
	var absent *X2SetupResponseIEValue
	selectedAssert(t, absent)
	v := X2SetupResponseIEValue{}
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
		v := X2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(21)
		selectedAssert(t, &v)
		v.rowGlobalENBID = new(s05.GlobalENBID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(20)
		selectedAssert(t, &v)
		v.rowServedCells = new(ServedCells)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(24)
		selectedAssert(t, &v)
		v.rowGUGroupIDList = new(s08.GUGroupIDList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := X2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(159)
		selectedAssert(t, &v)
		v.rowLHNID = new(s00.LHNID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union X2SetupResponseIEValue: 5 synthetic rows")
}
