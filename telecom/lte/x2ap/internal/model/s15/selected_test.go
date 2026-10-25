// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s15

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s01"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
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
func TestSelectedDataForwardingAddressIndicationIEValue(t *testing.T) {
	var absent *DataForwardingAddressIndicationIEValue
	selectedAssert(t, absent)
	v := DataForwardingAddressIndicationIEValue{}
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
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(307)
		selectedAssert(t, &v)
		v.rowERABsDataForwardingAddressList = new(s11.ERABsDataForwardingAddressList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(368)
		selectedAssert(t, &v)
		v.rowCHODCIndicator = new(s00.CHODCIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(407)
		selectedAssert(t, &v)
		v.rowCHODCEarlyDataForwarding = new(s00.CHODCEarlyDataForwarding)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := DataForwardingAddressIndicationIEValue{}
		v.id = s00.ProtocolIEID(431)
		selectedAssert(t, &v)
		v.rowCPCinformationNOTIFY = new(s01.CPCinformationNOTIFY)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union DataForwardingAddressIndicationIEValue: 9 synthetic rows")
}
func TestSelectedENBEUTRANRCellResourceCoordinationReqAckIEValue(t *testing.T) {
	var absent *ENBEUTRANRCellResourceCoordinationReqAckIEValue
	selectedAssert(t, absent)
	v := ENBEUTRANRCellResourceCoordinationReqAckIEValue{}
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
		v := ENBEUTRANRCellResourceCoordinationReqAckIEValue{}
		v.id = s00.ProtocolIEID(287)
		selectedAssert(t, &v)
		v.rowDataTrafficResourceIndication = new(s12.DataTrafficResourceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBEUTRANRCellResourceCoordinationReqAckIEValue{}
		v.id = s00.ProtocolIEID(288)
		selectedAssert(t, &v)
		v.rowSpectrumSharingGroupID = new(s08.SpectrumSharingGroupID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBEUTRANRCellResourceCoordinationReqAckIEValue{}
		v.id = s00.ProtocolIEID(290)
		selectedAssert(t, &v)
		v.rowListofEUTRACellsinEUTRACoordinationResp = new(s08.ListofEUTRACellsinEUTRACoordinationResp)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBEUTRANRCellResourceCoordinationReqAckIEValue: 3 synthetic rows")
}
func TestSelectedENBEUTRANRCellResourceCoordinationReqIEValue(t *testing.T) {
	var absent *ENBEUTRANRCellResourceCoordinationReqIEValue
	selectedAssert(t, absent)
	v := ENBEUTRANRCellResourceCoordinationReqIEValue{}
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
		v := ENBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(287)
		selectedAssert(t, &v)
		v.rowDataTrafficResourceIndication = new(s12.DataTrafficResourceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(288)
		selectedAssert(t, &v)
		v.rowSpectrumSharingGroupID = new(s08.SpectrumSharingGroupID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := ENBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(289)
		selectedAssert(t, &v)
		v.rowListofEUTRACellsinEUTRACoordinationReq = new(s08.ListofEUTRACellsinEUTRACoordinationReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union ENBEUTRANRCellResourceCoordinationReqIEValue: 3 synthetic rows")
}
func TestSelectedEnGNBEUTRANRCellResourceCoordinationReqIEValue(t *testing.T) {
	var absent *EnGNBEUTRANRCellResourceCoordinationReqIEValue
	selectedAssert(t, absent)
	v := EnGNBEUTRANRCellResourceCoordinationReqIEValue{}
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
		v := EnGNBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(287)
		selectedAssert(t, &v)
		v.rowDataTrafficResourceIndication = new(s12.DataTrafficResourceIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EnGNBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(291)
		selectedAssert(t, &v)
		v.rowListofEUTRACellsinNRCoordinationReq = new(s08.ListofEUTRACellsinNRCoordinationReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EnGNBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(288)
		selectedAssert(t, &v)
		v.rowSpectrumSharingGroupID = new(s08.SpectrumSharingGroupID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := EnGNBEUTRANRCellResourceCoordinationReqIEValue{}
		v.id = s00.ProtocolIEID(292)
		selectedAssert(t, &v)
		v.rowListofNRCellsinNRCoordinationReq = new(s08.ListofNRCellsinNRCoordinationReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union EnGNBEUTRANRCellResourceCoordinationReqIEValue: 4 synthetic rows")
}
func TestSelectedSNStatusTransferIEValue(t *testing.T) {
	var absent *SNStatusTransferIEValue
	selectedAssert(t, absent)
	v := SNStatusTransferIEValue{}
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
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(10)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(9)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(18)
		selectedAssert(t, &v)
		v.rowERABsSubjectToStatusTransferList = new(s08.ERABsSubjectToStatusTransferList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(156)
		selectedAssert(t, &v)
		v.rowOldENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(155)
		selectedAssert(t, &v)
		v.rowNewENBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SNStatusTransferIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SNStatusTransferIEValue: 6 synthetic rows")
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
func TestSelectedSeNBAdditionRequestIEValue(t *testing.T) {
	var absent *SeNBAdditionRequestIEValue
	selectedAssert(t, absent)
	v := SeNBAdditionRequestIEValue{}
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
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(113)
		selectedAssert(t, &v)
		v.rowUESecurityCapabilities = new(s06.UESecurityCapabilities)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(114)
		selectedAssert(t, &v)
		v.rowSeNBSecurityKey = new(s08.SeNBSecurityKey)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(115)
		selectedAssert(t, &v)
		v.rowSeNBUEAggregateMaximumBitRate = new(s08.UEAggregateMaximumBitRate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(116)
		selectedAssert(t, &v)
		v.rowServingPLMN = new(s00.PLMNIdentity)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(117)
		selectedAssert(t, &v)
		v.rowERABsToBeAddedList = new(s11.ERABsToBeAddedList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(119)
		selectedAssert(t, &v)
		v.rowMeNBtoSeNBContainer = new(s00.MeNBtoSeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(71)
		selectedAssert(t, &v)
		v.rowCSGMembershipStatus = new(s00.CSGMembershipStatus)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(104)
		selectedAssert(t, &v)
		v.rowExpectedUEBehaviour = new(s05.ExpectedUEBehaviour)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBAdditionRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBAdditionRequestIEValue: 12 synthetic rows")
}
func TestSelectedSeNBCounterCheckRequestIEValue(t *testing.T) {
	var absent *SeNBCounterCheckRequestIEValue
	selectedAssert(t, absent)
	v := SeNBCounterCheckRequestIEValue{}
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
		v := SeNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(141)
		selectedAssert(t, &v)
		v.rowERABsSubjectToCounterCheckList = new(s08.ERABsSubjectToCounterCheckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBCounterCheckRequestIEValue: 5 synthetic rows")
}
func TestSelectedSeNBModificationRequestAcknowledgeIEValue(t *testing.T) {
	var absent *SeNBModificationRequestAcknowledgeIEValue
	selectedAssert(t, absent)
	v := SeNBModificationRequestAcknowledgeIEValue{}
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
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(128)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeAddedModAckList = new(s11.ERABsAdmittedToBeAddedModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(129)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedModAckList = new(s11.ERABsAdmittedToBeModifiedModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(130)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeReleasedModAckList = new(s08.ERABsAdmittedToBeReleasedModAckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(3)
		selectedAssert(t, &v)
		v.rowERABsNotAdmittedList = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(122)
		selectedAssert(t, &v)
		v.rowSeNBtoMeNBContainer = new(s08.SeNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequestAcknowledgeIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBModificationRequestAcknowledgeIEValue: 10 synthetic rows")
}
func TestSelectedSeNBModificationRequiredIEValue(t *testing.T) {
	var absent *SeNBModificationRequiredIEValue
	selectedAssert(t, absent)
	v := SeNBModificationRequiredIEValue{}
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
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(136)
		selectedAssert(t, &v)
		v.rowSCGChangeIndication = new(s00.SCGChangeIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(134)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedModReqd = new(s08.ERABsToBeReleasedModReqd)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(122)
		selectedAssert(t, &v)
		v.rowSeNBtoMeNBContainer = new(s08.SeNBtoMeNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBModificationRequiredIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBModificationRequiredIEValue: 8 synthetic rows")
}
func TestSelectedSeNBReleaseConfirmIEValue(t *testing.T) {
	var absent *SeNBReleaseConfirmIEValue
	selectedAssert(t, absent)
	v := SeNBReleaseConfirmIEValue{}
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
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(139)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedListRelConf = new(s11.ERABsToBeReleasedListRelConf)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBReleaseConfirmIEValue: 6 synthetic rows")
}
func TestSelectedSeNBReleaseRequestIEValue(t *testing.T) {
	var absent *SeNBReleaseRequestIEValue
	selectedAssert(t, absent)
	v := SeNBReleaseRequestIEValue{}
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
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(112)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(137)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedListRelReq = new(s11.ERABsToBeReleasedListRelReq)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(154)
		selectedAssert(t, &v)
		v.rowUEContextKeptIndicator = new(s00.UEContextKeptIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(158)
		selectedAssert(t, &v)
		v.rowSeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SeNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(181)
		selectedAssert(t, &v)
		v.rowMakeBeforeBreakIndicator = new(s00.MakeBeforeBreakIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SeNBReleaseRequestIEValue: 8 synthetic rows")
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
func TestSelectedSgNBChangeConfirmIEValue(t *testing.T) {
	var absent *SgNBChangeConfirmIEValue
	selectedAssert(t, absent)
	v := SgNBChangeConfirmIEValue{}
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
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(229)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBChaConfList = new(s14.ERABsToBeReleasedSgNBChaConfList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(430)
		selectedAssert(t, &v)
		v.rowCPCinformationCONF = new(s06.CPCinformationCONF)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBChangeConfirmIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBChangeConfirmIEValue: 7 synthetic rows")
}
func TestSelectedSgNBCounterCheckRequestIEValue(t *testing.T) {
	var absent *SgNBCounterCheckRequestIEValue
	selectedAssert(t, absent)
	v := SgNBCounterCheckRequestIEValue{}
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
		v := SgNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(235)
		selectedAssert(t, &v)
		v.rowERABsSubjectToSgNBCounterCheckList = new(s08.ERABsSubjectToSgNBCounterCheckList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBCounterCheckRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBCounterCheckRequestIEValue: 4 synthetic rows")
}
func TestSelectedSgNBModificationConfirmIEValue(t *testing.T) {
	var absent *SgNBModificationConfirmIEValue
	selectedAssert(t, absent)
	v := SgNBModificationConfirmIEValue{}
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
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(294)
		selectedAssert(t, &v)
		v.rowERABsAdmittedToBeModifiedSgNBModConfList = new(s11.ERABsAdmittedToBeModifiedSgNBModConfList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBModificationConfirmIEValue{}
		v.id = s00.ProtocolIEID(257)
		selectedAssert(t, &v)
		v.rowMeNBResourceCoordinationInformation = new(s08.MeNBResourceCoordinationInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBModificationConfirmIEValue: 7 synthetic rows")
}
func TestSelectedSgNBReleaseConfirmIEValue(t *testing.T) {
	var absent *SgNBReleaseConfirmIEValue
	selectedAssert(t, absent)
	v := SgNBReleaseConfirmIEValue{}
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
		v := SgNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(233)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelConfList = new(s11.ERABsToBeReleasedSgNBRelConfList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(17)
		selectedAssert(t, &v)
		v.rowCriticalityDiagnostics = new(s06.CriticalityDiagnostics)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseConfirmIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReleaseConfirmIEValue: 5 synthetic rows")
}
func TestSelectedSgNBReleaseRequestIEValue(t *testing.T) {
	var absent *SgNBReleaseRequestIEValue
	selectedAssert(t, absent)
	v := SgNBReleaseRequestIEValue{}
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
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(111)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APID = new(s11.UEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(207)
		selectedAssert(t, &v)
		v.rowSgNBUEX2APID = new(s08.SgNBUEX2APID)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(5)
		selectedAssert(t, &v)
		v.rowCause = new(s00.Cause)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(231)
		selectedAssert(t, &v)
		v.rowERABsToBeReleasedSgNBRelReqList = new(s11.ERABsToBeReleasedSgNBRelReqList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(154)
		selectedAssert(t, &v)
		v.rowUEContextKeptIndicator = new(s00.UEContextKeptIndicator)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(157)
		selectedAssert(t, &v)
		v.rowMeNBUEX2APIDExtension = new(s11.UEX2APIDExtension)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(206)
		selectedAssert(t, &v)
		v.rowMeNBtoSgNBContainer = new(s00.MeNBtoSgNBContainer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := SgNBReleaseRequestIEValue{}
		v.id = s00.ProtocolIEID(339)
		selectedAssert(t, &v)
		v.rowERABsTransferredToMeNB = new(s08.ERABList)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union SgNBReleaseRequestIEValue: 8 synthetic rows")
}
