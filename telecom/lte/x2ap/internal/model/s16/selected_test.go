// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s16

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
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
func TestSelectedAccessAndMobilityIndicationIEValue(t *testing.T) {
	var absent *AccessAndMobilityIndicationIEValue
	selectedAssert(t, absent)
	v := AccessAndMobilityIndicationIEValue{}
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
		v := AccessAndMobilityIndicationIEValue{}
		v.id = s00.ProtocolIEID(414)
		selectedAssert(t, &v)
		v.rowNRRAReport = new(s08.NRRAReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union AccessAndMobilityIndicationIEValue: 1 synthetic rows")
}
func TestSelectedFDDInfoNeighbourServedNRCellInformationExtIEsValue(t *testing.T) {
	var absent *FDDInfoNeighbourServedNRCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := FDDInfoNeighbourServedNRCellInformationExtIEsValue{}
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
		v := FDDInfoNeighbourServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(387)
		selectedAssert(t, &v)
		v.rowULCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union FDDInfoNeighbourServedNRCellInformationExtIEsValue: 1 synthetic rows")
}
func TestSelectedFDDInfoServedNRCellInformationExtIEsValue(t *testing.T) {
	var absent *FDDInfoServedNRCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := FDDInfoServedNRCellInformationExtIEsValue{}
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
		v := FDDInfoServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(387)
		selectedAssert(t, &v)
		v.rowULCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := FDDInfoServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(381)
		selectedAssert(t, &v)
		v.rowDLCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union FDDInfoServedNRCellInformationExtIEsValue: 2 synthetic rows")
}
func TestSelectedHandoverRestrictionListExtIEsValue(t *testing.T) {
	var absent *HandoverRestrictionListExtIEsValue
	selectedAssert(t, absent)
	v := HandoverRestrictionListExtIEsValue{}
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
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(202)
		selectedAssert(t, &v)
		v.rowNRrestrictioninEPSasSecondaryRAT = new(s00.NRrestrictioninEPSasSecondaryRAT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(301)
		selectedAssert(t, &v)
		v.rowCNTypeRestrictions = new(s06.CNTypeRestrictions)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(305)
		selectedAssert(t, &v)
		v.rowNRrestrictionin5GS = new(s00.NRrestrictionin5GS)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(332)
		selectedAssert(t, &v)
		v.rowLastNGRANPLMNIdentity = new(s00.PLMNIdentity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(358)
		selectedAssert(t, &v)
		v.rowUnlicensedSpectrumRestriction = new(s00.UnlicensedSpectrumRestriction)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRestrictionListExtIEsValue{}
		v.id = s00.ProtocolIEID(437)
		selectedAssert(t, &v)
		v.rowRATRestrictions = new(s08.RATRestrictions)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverRestrictionListExtIEsValue: 6 synthetic rows")
}
func TestSelectedLastVisitedEUTRANCellInformationExtIEsValue(t *testing.T) {
	var absent *LastVisitedEUTRANCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := LastVisitedEUTRANCellInformationExtIEsValue{}
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
		v := LastVisitedEUTRANCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(77)
		selectedAssert(t, &v)
		v.rowTimeUEStayedInCellEnhancedGranularity = new(s09.TimeUEStayedInCellEnhancedGranularity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := LastVisitedEUTRANCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(80)
		selectedAssert(t, &v)
		v.rowHOCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := LastVisitedEUTRANCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(418)
		selectedAssert(t, &v)
		v.rowPSCellUEHistoryInformation = new(s00.PSCellUEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union LastVisitedEUTRANCellInformationExtIEsValue: 3 synthetic rows")
}
func TestSelectedMDTConfigurationExtIEsValue(t *testing.T) {
	var absent *MDTConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := MDTConfigurationExtIEsValue{}
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
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(85)
		selectedAssert(t, &v)
		v.rowM3Configuration = new(s05.M3Configuration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(86)
		selectedAssert(t, &v)
		v.rowM4Configuration = new(s07.M4Configuration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(87)
		selectedAssert(t, &v)
		v.rowM5Configuration = new(s07.M5Configuration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(88)
		selectedAssert(t, &v)
		v.rowMDTLocationInfo = new(s00.MDTLocationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(90)
		selectedAssert(t, &v)
		v.rowSignallingBasedMDTPLMNList = new(s00.MDTPLMNList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(161)
		selectedAssert(t, &v)
		v.rowM6Configuration = new(s08.M6Configuration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(162)
		selectedAssert(t, &v)
		v.rowM7Configuration = new(s08.M7Configuration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(303)
		selectedAssert(t, &v)
		v.rowBluetoothMeasurementConfiguration = new(s01.BluetoothMeasurementConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(304)
		selectedAssert(t, &v)
		v.rowWLANMeasurementConfiguration = new(s13.WLANMeasurementConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := MDTConfigurationExtIEsValue{}
		v.id = s00.ProtocolIEID(440)
		selectedAssert(t, &v)
		v.rowSensorMeasurementConfiguration = new(s08.SensorMeasurementConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union MDTConfigurationExtIEsValue: 10 synthetic rows")
}
func TestSelectedResourceStatusResponseIEValue(t *testing.T) {
	var absent *ResourceStatusResponseIEValue
	selectedAssert(t, absent)
	v := ResourceStatusResponseIEValue{}
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
		v := ResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(39)
		selectedAssert(t, &v)
		v.rowENB1MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(40)
		selectedAssert(t, &v)
		v.rowENB2MeasurementID = new(s00.MeasurementID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ResourceStatusResponseIEValue{}
		v.id = s00.ProtocolIEID(65)
		selectedAssert(t, &v)
		v.rowMeasurementInitiationResultList = new(s08.MeasurementInitiationResultList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ResourceStatusResponseIEValue: 4 synthetic rows")
}
func TestSelectedSULInformationExtIEsValue(t *testing.T) {
	var absent *SULInformationExtIEsValue
	selectedAssert(t, absent)
	v := SULInformationExtIEsValue{}
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
		v := SULInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(386)
		selectedAssert(t, &v)
		v.rowCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SULInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(388)
		selectedAssert(t, &v)
		v.rowFrequencyShift7p5khz = new(s00.FrequencyShift7p5khz)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SULInformationExtIEsValue: 2 synthetic rows")
}
func TestSelectedServedCellInformationExtIEsValue(t *testing.T) {
	var absent *ServedCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := ServedCellInformationExtIEsValue{}
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
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(41)
		selectedAssert(t, &v)
		v.rowNumberOfAntennaports = new(s00.NumberOfAntennaports)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(55)
		selectedAssert(t, &v)
		v.rowPRACHConfiguration = new(s05.PRACHConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(56)
		selectedAssert(t, &v)
		v.rowMBSFNSubframeInfo = new(s08.MBSFNSubframeInfolist)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(70)
		selectedAssert(t, &v)
		v.rowCSGId = new(s00.CSGId)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(79)
		selectedAssert(t, &v)
		v.rowMBMSServiceAreaList = new(s00.MBMSServiceAreaIdentityList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(84)
		selectedAssert(t, &v)
		v.rowMultibandInfoList = new(s08.MultibandInfoList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(160)
		selectedAssert(t, &v)
		v.rowFreqBandIndicatorPriority = new(s00.FreqBandIndicatorPriority)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(180)
		selectedAssert(t, &v)
		v.rowBandwidthReducedSI = new(s00.BandwidthReducedSI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(284)
		selectedAssert(t, &v)
		v.rowProtectedEUTRAResourceIndication = new(s08.ProtectedEUTRAResourceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(336)
		selectedAssert(t, &v)
		v.rowBPLMNIDInfoEUTRA = new(s09.BPLMNIDInfoEUTRA)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(373)
		selectedAssert(t, &v)
		v.rowNPRACHConfiguration = new(s08.NPRACHConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(406)
		selectedAssert(t, &v)
		v.rowSFNOffset = new(s05.SFNOffset)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ServedCellInformationExtIEsValue: 12 synthetic rows")
}
func TestSelectedServedCellsToModifyItemExtIEsValue(t *testing.T) {
	var absent *ServedCellsToModifyItemExtIEsValue
	selectedAssert(t, absent)
	v := ServedCellsToModifyItemExtIEsValue{}
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
		v := ServedCellsToModifyItemExtIEsValue{}
		v.id = s00.ProtocolIEID(59)
		selectedAssert(t, &v)
		v.rowDeactivationIndication = new(s00.DeactivationIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ServedCellsToModifyItemExtIEsValue{}
		v.id = s00.ProtocolIEID(328)
		selectedAssert(t, &v)
		v.rowNRNeighbourInfoToModify = new(NRNeighbourInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ServedCellsToModifyItemExtIEsValue: 2 synthetic rows")
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
		v.rowHandoverRestrictionList = new(HandoverRestrictionList)
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
func TestSelectedTDDInfoNeighbourServedNRCellInformationExtIEsValue(t *testing.T) {
	var absent *TDDInfoNeighbourServedNRCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := TDDInfoNeighbourServedNRCellInformationExtIEsValue{}
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
		v := TDDInfoNeighbourServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(399)
		selectedAssert(t, &v)
		v.rowIntendedTDDDLULConfigurationNR = new(s00.IntendedTDDDLULConfigurationNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoNeighbourServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(385)
		selectedAssert(t, &v)
		v.rowTDDULDLConfigurationCommonNR = new(s09.TDDULDLConfigurationCommonNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoNeighbourServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(386)
		selectedAssert(t, &v)
		v.rowCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union TDDInfoNeighbourServedNRCellInformationExtIEsValue: 3 synthetic rows")
}
func TestSelectedTDDInfoServedNRCellInformationExtIEsValue(t *testing.T) {
	var absent *TDDInfoServedNRCellInformationExtIEsValue
	selectedAssert(t, absent)
	v := TDDInfoServedNRCellInformationExtIEsValue{}
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
		v := TDDInfoServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(385)
		selectedAssert(t, &v)
		v.rowTDDULDLConfigurationCommonNR = new(s09.TDDULDLConfigurationCommonNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(386)
		selectedAssert(t, &v)
		v.rowCarrierList = new(s08.NRCarrierList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TDDInfoServedNRCellInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(399)
		selectedAssert(t, &v)
		v.rowIntendedTDDDLULConfigurationNR = new(s00.IntendedTDDDLULConfigurationNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union TDDInfoServedNRCellInformationExtIEsValue: 3 synthetic rows")
}
func TestSelectedTraceActivationExtIEsValue(t *testing.T) {
	var absent *TraceActivationExtIEsValue
	selectedAssert(t, absent)
	v := TraceActivationExtIEsValue{}
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
		v := TraceActivationExtIEsValue{}
		v.id = s00.ProtocolIEID(72)
		selectedAssert(t, &v)
		v.rowMDTConfiguration = new(MDTConfiguration)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceActivationExtIEsValue{}
		v.id = s00.ProtocolIEID(195)
		selectedAssert(t, &v)
		v.rowUEAppLayerMeasConfig = new(s09.UEAppLayerMeasConfig)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceActivationExtIEsValue{}
		v.id = s00.ProtocolIEID(375)
		selectedAssert(t, &v)
		v.rowMDTConfigurationNR = new(s00.MDTConfigurationNR)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceActivationExtIEsValue{}
		v.id = s00.ProtocolIEID(405)
		selectedAssert(t, &v)
		v.rowTraceCollectionEntityURI = new(s12.URIAddress)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union TraceActivationExtIEsValue: 4 synthetic rows")
}
func TestSelectedTraceStartIEValue(t *testing.T) {
	var absent *TraceStartIEValue
	selectedAssert(t, absent)
	v := TraceStartIEValue{}
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
		v := TraceStartIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceStartIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceStartIEValue{}
		v.id = s00.ProtocolIEID(13)
		selectedAssert(t, &v)
		v.rowTraceActivation = new(TraceActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := TraceStartIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union TraceStartIEValue: 4 synthetic rows")
}
func TestSelectedUEContextInformationExtIEsValue(t *testing.T) {
	var absent *UEContextInformationExtIEsValue
	selectedAssert(t, absent)
	v := UEContextInformationExtIEsValue{}
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
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(74)
		selectedAssert(t, &v)
		v.rowManagementBasedMDTallowed = new(s00.ManagementBasedMDTallowed)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(89)
		selectedAssert(t, &v)
		v.rowManagementBasedMDTPLMNList = new(s00.MDTPLMNList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(184)
		selectedAssert(t, &v)
		v.rowUESidelinkAggregateMaximumBitRate = new(s06.UESidelinkAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(360)
		selectedAssert(t, &v)
		v.rowEPCHandoverRestrictionListContainer = new(s00.EPCHandoverRestrictionListContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(340)
		selectedAssert(t, &v)
		v.rowAdditionalRRMPriorityIndex = new(s00.AdditionalRRMPriorityIndex)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(371)
		selectedAssert(t, &v)
		v.rowNRUESidelinkAggregateMaximumBitRate = new(s05.NRUESidelinkAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(378)
		selectedAssert(t, &v)
		v.rowUERadioCapabilityID = new(s11.UERadioCapabilityID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := UEContextInformationExtIEsValue{}
		v.id = s00.ProtocolIEID(408)
		selectedAssert(t, &v)
		v.rowIMSvoiceEPSfallbackfrom5G = new(s00.IMSvoiceEPSfallbackfrom5G)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union UEContextInformationExtIEsValue: 8 synthetic rows")
}
