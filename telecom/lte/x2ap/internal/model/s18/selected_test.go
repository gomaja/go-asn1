// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s18

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
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
func TestSelectedENDCConfigurationUpdateAcknowledgeIEValue(t *testing.T) {
	var absent *ENDCConfigurationUpdateAcknowledgeIEValue
	selectedAssert(t, absent)
	v := ENDCConfigurationUpdateAcknowledgeIEValue{}
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
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(247)
		selectedAssert(t, &v)
		v.rowRespondingNodeTypeEndcConfigUpdate = new(s17.RespondingNodeTypeEndcConfigUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(352)
		selectedAssert(t, &v)
		v.rowTNLConfigurationInfo = new(s11.TNLConfigurationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(356)
		selectedAssert(t, &v)
		v.rowTNLASetupList = new(s11.TNLASetupList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(357)
		selectedAssert(t, &v)
		v.rowTNLAFailedToSetupList = new(s11.TNLAFailedToSetupList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCConfigurationUpdateAcknowledgeIEValue: 6 synthetic rows")
}
func TestSelectedENDCConfigurationUpdateIEValue(t *testing.T) {
	var absent *ENDCConfigurationUpdateIEValue
	selectedAssert(t, absent)
	v := ENDCConfigurationUpdateIEValue{}
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
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(245)
		selectedAssert(t, &v)
		v.rowInitiatingNodeTypeEndcConfigUpdate = new(InitiatingNodeTypeEndcConfigUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(352)
		selectedAssert(t, &v)
		v.rowTNLConfigurationInfo = new(s11.TNLConfigurationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(353)
		selectedAssert(t, &v)
		v.rowTNLAToAddList = new(s11.TNLAToAddList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(354)
		selectedAssert(t, &v)
		v.rowTNLAToUpdateList = new(s11.TNLAToUpdateList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCConfigurationUpdateIEValue{}
		v.id = s00.ProtocolIEID(355)
		selectedAssert(t, &v)
		v.rowTNLAToRemoveList = new(s11.TNLAToRemoveList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCConfigurationUpdateIEValue: 6 synthetic rows")
}
func TestSelectedENDCPartialResetConfirmIEValue(t *testing.T) {
	var absent *ENDCPartialResetConfirmIEValue
	selectedAssert(t, absent)
	v := ENDCPartialResetConfirmIEValue{}
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
		v := ENDCPartialResetConfirmIEValue{}
		v.id = s00.ProtocolIEID(271)
		selectedAssert(t, &v)
		v.rowUEsAdmittedToBeReset = new(s12.UEsToBeResetList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCPartialResetConfirmIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCPartialResetConfirmIEValue: 2 synthetic rows")
}
func TestSelectedENDCPartialResetRequiredIEValue(t *testing.T) {
	var absent *ENDCPartialResetRequiredIEValue
	selectedAssert(t, absent)
	v := ENDCPartialResetRequiredIEValue{}
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
		v := ENDCPartialResetRequiredIEValue{}
		v.id = s00.ProtocolIEID(270)
		selectedAssert(t, &v)
		v.rowUEsToBeReset = new(s12.UEsToBeResetList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCPartialResetRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCPartialResetRequiredIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCPartialResetRequiredIEValue: 3 synthetic rows")
}
func TestSelectedENDCX2SetupRequestIEValue(t *testing.T) {
	var absent *ENDCX2SetupRequestIEValue
	selectedAssert(t, absent)
	v := ENDCX2SetupRequestIEValue{}
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
		v := ENDCX2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(244)
		selectedAssert(t, &v)
		v.rowInitiatingNodeTypeEndcX2Setup = new(InitiatingNodeTypeEndcX2Setup)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupRequestIEValue{}
		v.id = s00.ProtocolIEID(352)
		selectedAssert(t, &v)
		v.rowTNLConfigurationInfo = new(s11.TNLConfigurationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2SetupRequestIEValue: 3 synthetic rows")
}
func TestSelectedENDCX2SetupResponseIEValue(t *testing.T) {
	var absent *ENDCX2SetupResponseIEValue
	selectedAssert(t, absent)
	v := ENDCX2SetupResponseIEValue{}
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
		v := ENDCX2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(246)
		selectedAssert(t, &v)
		v.rowRespondingNodeTypeEndcX2Setup = new(s17.RespondingNodeTypeEndcX2Setup)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(335)
		selectedAssert(t, &v)
		v.rowInterfaceInstanceIndication = new(s00.InterfaceInstanceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENDCX2SetupResponseIEValue{}
		v.id = s00.ProtocolIEID(352)
		selectedAssert(t, &v)
		v.rowTNLConfigurationInfo = new(s11.TNLConfigurationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENDCX2SetupResponseIEValue: 3 synthetic rows")
}
func TestSelectedEnGNBENDCConfigUpdateIEValue(t *testing.T) {
	var absent *EnGNBENDCConfigUpdateIEValue
	selectedAssert(t, absent)
	v := EnGNBENDCConfigUpdateIEValue{}
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
		v := EnGNBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(253)
		selectedAssert(t, &v)
		v.rowServedNRcellsENDCX2ManagementList = new(s17.ServedNRcellsENDCX2ManagementList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EnGNBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(261)
		selectedAssert(t, &v)
		v.rowServedNRcellsToModifyListENDCConfUpd = new(s16.ServedNRcellsToModifyENDCConfUpdList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EnGNBENDCConfigUpdateIEValue{}
		v.id = s00.ProtocolIEID(262)
		selectedAssert(t, &v)
		v.rowServedNRcellsToDeleteListENDCConfUpd = new(s08.ServedNRcellsToDeleteENDCConfUpdList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EnGNBENDCConfigUpdateIEValue: 3 synthetic rows")
}
func TestSelectedHandoverRequestIEValue(t *testing.T) {
	var absent *HandoverRequestIEValue
	selectedAssert(t, absent)
	v := HandoverRequestIEValue{}
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
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(11)
		selectedAssert(t, &v)
		v.rowTargetCellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(23)
		selectedAssert(t, &v)
		v.rowGUMMEIID = new(s05.GUMMEI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(14)
		selectedAssert(t, &v)
		v.rowUEContextInformation = new(s16.UEContextInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(15)
		selectedAssert(t, &v)
		v.rowUEHistoryInformation = new(s16.UEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(13)
		selectedAssert(t, &v)
		v.rowTraceActivation = new(s16.TraceActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(36)
		selectedAssert(t, &v)
		v.rowSRVCCOperationPossible = new(s00.SRVCCOperationPossible)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(71)
		selectedAssert(t, &v)
		v.rowCSGMembershipStatus = new(s00.CSGMembershipStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(82)
		selectedAssert(t, &v)
		v.rowMobilityInformation = new(s00.MobilityInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(98)
		selectedAssert(t, &v)
		v.rowMaskedIMEISV = new(s00.MaskedIMEISV)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(105)
		selectedAssert(t, &v)
		v.rowUEHistoryInformationFromTheUE = new(s11.UEHistoryInformationFromTheUE)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(104)
		selectedAssert(t, &v)
		v.rowExpectedUEBehaviour = new(s05.ExpectedUEBehaviour)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(103)
		selectedAssert(t, &v)
		v.rowProSeAuthorized = new(s08.ProSeAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(153)
		selectedAssert(t, &v)
		v.rowUEContextReferenceAtSeNB = new(s12.UEContextReferenceAtSeNB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(176)
		selectedAssert(t, &v)
		v.rowV2XServicesAuthorized = new(s06.V2XServicesAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(182)
		selectedAssert(t, &v)
		v.rowUEContextReferenceAtWT = new(s13.UEContextReferenceAtWT)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(248)
		selectedAssert(t, &v)
		v.rowNRUESecurityCapabilities = new(s05.NRUESecurityCapabilities)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(254)
		selectedAssert(t, &v)
		v.rowUEContextReferenceAtSgNB = new(s08.UEContextReferenceAtSgNB)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(277)
		selectedAssert(t, &v)
		v.rowAerialUEsubscriptionInformation = new(s00.AerialUEsubscriptionInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(309)
		selectedAssert(t, &v)
		v.rowSubscriptionBasedUEDifferentiationInfo = new(s05.SubscriptionBasedUEDifferentiationInfo)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(361)
		selectedAssert(t, &v)
		v.rowCHOinformationREQ = new(s11.CHOinformationREQ)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(370)
		selectedAssert(t, &v)
		v.rowNRV2XServicesAuthorized = new(s05.NRV2XServicesAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(372)
		selectedAssert(t, &v)
		v.rowPC5QoSParameters = new(s08.PC5QoSParameters)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := HandoverRequestIEValue{}
		v.id = s00.ProtocolIEID(395)
		selectedAssert(t, &v)
		v.rowIABNodeIndication = new(s00.IABNodeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union HandoverRequestIEValue: 26 synthetic rows")
}
func TestSelectedSgNBAdditionRequestIEValue(t *testing.T) {
	var absent *SgNBAdditionRequestIEValue
	selectedAssert(t, absent)
	v := SgNBAdditionRequestIEValue{}
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
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(248)
		selectedAssert(t, &v)
		v.rowNRUESecurityCapabilities = new(s05.NRUESecurityCapabilities)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(203)
		selectedAssert(t, &v)
		v.rowSgNBSecurityKey = new(s08.SgNBSecurityKey)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(204)
		selectedAssert(t, &v)
		v.rowSgNBUEAggregateMaximumBitRate = new(s08.UEAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(269)
		selectedAssert(t, &v)
		v.rowSelectedPLMN = new(s00.PLMNIdentity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(240)
		selectedAssert(t, &v)
		v.rowHandoverRestrictionList = new(s16.HandoverRestrictionList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(205)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedSgNBAddReqList = new(s11.ERABsToBeAddedSgNBAddReqList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(104)
		selectedAssert(t, &v)
		v.rowExpectedUEBehaviour = new(s05.ExpectedUEBehaviour)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(208)
		selectedAssert(t, &v)
		v.rowRequestedSplitSRBs = new(s00.SplitSRBs)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(257)
		selectedAssert(t, &v)
		v.rowMeNBResourceCoordinationInformation = new(s08.MeNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(278)
		selectedAssert(t, &v)
		v.rowSGNBAdditionTriggerInd = new(s00.SGNBAdditionTriggerInd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(275)
		selectedAssert(t, &v)
		v.rowSubscriberProfileIDforRFP = new(s08.SubscriberProfileIDforRFP)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(279)
		selectedAssert(t, &v)
		v.rowMeNBCellID = new(s04.ECGI)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(329)
		selectedAssert(t, &v)
		v.rowDesiredActNotificationLevel = new(s00.DesiredActNotificationLevel)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(13)
		selectedAssert(t, &v)
		v.rowTraceActivation = new(s16.TraceActivation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(330)
		selectedAssert(t, &v)
		v.rowLocationInformationSgNBReporting = new(s00.LocationInformationSgNBReporting)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(98)
		selectedAssert(t, &v)
		v.rowMaskedIMEISV = new(s00.MaskedIMEISV)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(340)
		selectedAssert(t, &v)
		v.rowAdditionalRRMPriorityIndex = new(s00.AdditionalRRMPriorityIndex)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(343)
		selectedAssert(t, &v)
		v.rowRequestedFastMCGRecoveryViaSRB3 = new(s00.RequestedFastMCGRecoveryViaSRB3)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(359)
		selectedAssert(t, &v)
		v.rowUEContextReferenceatSourceNGRAN = new(s08.RANUENGAPID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(74)
		selectedAssert(t, &v)
		v.rowManagementBasedMDTallowed = new(s00.ManagementBasedMDTallowed)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(89)
		selectedAssert(t, &v)
		v.rowManagementBasedMDTPLMNList = new(s00.MDTPLMNList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(378)
		selectedAssert(t, &v)
		v.rowUERadioCapabilityID = new(s11.UERadioCapabilityID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(395)
		selectedAssert(t, &v)
		v.rowIABNodeIndication = new(s00.IABNodeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(411)
		selectedAssert(t, &v)
		v.rowSourceNGRANNodeId = new(s05.GlobalRANNODEID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(15)
		selectedAssert(t, &v)
		v.rowUEHistoryInformation = new(s16.UEHistoryInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(105)
		selectedAssert(t, &v)
		v.rowUEHistoryInformationFromTheUE = new(s11.UEHistoryInformationFromTheUE)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(419)
		selectedAssert(t, &v)
		v.rowPSCellChangeHistory = new(s00.PSCellChangeHistory)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(420)
		selectedAssert(t, &v)
		v.rowCHOinformationAddReq = new(s11.CHOinformationAddReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(423)
		selectedAssert(t, &v)
		v.rowSCGActivationRequest = new(s00.SCGActivationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(424)
		selectedAssert(t, &v)
		v.rowCPAinformationREQ = new(s01.CPAinformationREQ)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(449)
		selectedAssert(t, &v)
		v.rowIABAuthorized = new(s00.IABAuthorized)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBAdditionRequestIEValue: 35 synthetic rows")
}
func TestSelectedSuccessfulValue(t *testing.T) {
	var absent *SuccessfulValue
	selectedAssert(t, absent)
	v := SuccessfulValue{}
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
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(0)
		selectedAssert(t, &v)
		v.bodyHandoverRequestAcknowledge = new(HandoverRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(6)
		selectedAssert(t, &v)
		v.bodyX2SetupResponse = new(X2SetupResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(7)
		selectedAssert(t, &v)
		v.bodyResetResponse = new(ResetResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(8)
		selectedAssert(t, &v)
		v.bodyENBConfigurationUpdateAcknowledge = new(ENBConfigurationUpdateAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(9)
		selectedAssert(t, &v)
		v.bodyResourceStatusResponse = new(ResourceStatusResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(12)
		selectedAssert(t, &v)
		v.bodyMobilityChangeAcknowledge = new(MobilityChangeAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(15)
		selectedAssert(t, &v)
		v.bodyCellActivationResponse = new(CellActivationResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(18)
		selectedAssert(t, &v)
		v.bodyX2RemovalResponse = new(X2RemovalResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(19)
		selectedAssert(t, &v)
		v.bodySeNBAdditionRequestAcknowledge = new(SeNBAdditionRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(21)
		selectedAssert(t, &v)
		v.bodySeNBModificationRequestAcknowledge = new(SeNBModificationRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(22)
		selectedAssert(t, &v)
		v.bodySeNBModificationConfirm = new(SeNBModificationConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(24)
		selectedAssert(t, &v)
		v.bodySeNBReleaseConfirm = new(SeNBReleaseConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(26)
		selectedAssert(t, &v)
		v.bodyRetrieveUEContextResponse = new(RetrieveUEContextResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(27)
		selectedAssert(t, &v)
		v.bodySgNBAdditionRequestAcknowledge = new(SgNBAdditionRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(29)
		selectedAssert(t, &v)
		v.bodySgNBModificationRequestAcknowledge = new(SgNBModificationRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(30)
		selectedAssert(t, &v)
		v.bodySgNBModificationConfirm = new(SgNBModificationConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(31)
		selectedAssert(t, &v)
		v.bodySgNBReleaseRequestAcknowledge = new(SgNBReleaseRequestAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(32)
		selectedAssert(t, &v)
		v.bodySgNBReleaseConfirm = new(SgNBReleaseConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(34)
		selectedAssert(t, &v)
		v.bodySgNBChangeConfirm = new(SgNBChangeConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(36)
		selectedAssert(t, &v)
		v.bodyENDCX2SetupResponse = new(ENDCX2SetupResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(37)
		selectedAssert(t, &v)
		v.bodyENDCConfigurationUpdateAcknowledge = new(ENDCConfigurationUpdateAcknowledge)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(39)
		selectedAssert(t, &v)
		v.bodyENDCCellActivationResponse = new(ENDCCellActivationResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(40)
		selectedAssert(t, &v)
		v.bodyENDCPartialResetConfirm = new(ENDCPartialResetConfirm)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(41)
		selectedAssert(t, &v)
		v.bodyEUTRANRCellResourceCoordinationResponse = new(EUTRANRCellResourceCoordinationResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(43)
		selectedAssert(t, &v)
		v.bodyENDCX2RemovalResponse = new(ENDCX2RemovalResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(54)
		selectedAssert(t, &v)
		v.bodyENDCResourceStatusResponse = new(ENDCResourceStatusResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SuccessfulValue{}
		v.code = s00.ProcedureCode(56)
		selectedAssert(t, &v)
		v.bodyUERadioCapabilityIDMappingResponse = new(UERadioCapabilityIDMappingResponse)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SuccessfulValue: 27 synthetic rows")
}
