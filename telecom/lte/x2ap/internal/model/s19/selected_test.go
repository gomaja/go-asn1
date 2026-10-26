// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s19

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
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
func TestSelectedInitiatingValue(t *testing.T) {
	var absent *InitiatingValue
	selectedAssert(t, absent)
	v := InitiatingValue{}
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
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(0)
		selectedAssert(t, &v)
		v.bodyHandoverRequest = new(HandoverRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(1)
		selectedAssert(t, &v)
		v.bodyHandoverCancel = new(HandoverCancel)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(2)
		selectedAssert(t, &v)
		v.bodyLoadInformation = new(LoadInformation)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(3)
		selectedAssert(t, &v)
		v.bodyErrorIndication = new(ErrorIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(4)
		selectedAssert(t, &v)
		v.bodySNStatusTransfer = new(SNStatusTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(5)
		selectedAssert(t, &v)
		v.bodyUEContextRelease = new(UEContextRelease)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(6)
		selectedAssert(t, &v)
		v.bodyX2SetupRequest = new(X2SetupRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(7)
		selectedAssert(t, &v)
		v.bodyResetRequest = new(ResetRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(8)
		selectedAssert(t, &v)
		v.bodyENBConfigurationUpdate = new(ENBConfigurationUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(9)
		selectedAssert(t, &v)
		v.bodyResourceStatusRequest = new(ResourceStatusRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(10)
		selectedAssert(t, &v)
		v.bodyResourceStatusUpdate = new(ResourceStatusUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(11)
		selectedAssert(t, &v)
		v.bodyPrivateMessage = new(PrivateMessage)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(12)
		selectedAssert(t, &v)
		v.bodyMobilityChangeRequest = new(MobilityChangeRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(13)
		selectedAssert(t, &v)
		v.bodyRLFIndication = new(RLFIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(14)
		selectedAssert(t, &v)
		v.bodyHandoverReport = new(HandoverReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(15)
		selectedAssert(t, &v)
		v.bodyCellActivationRequest = new(CellActivationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(16)
		selectedAssert(t, &v)
		v.bodyX2Release = new(X2Release)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(17)
		selectedAssert(t, &v)
		v.bodyX2APMessageTransfer = new(X2APMessageTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(18)
		selectedAssert(t, &v)
		v.bodyX2RemovalRequest = new(X2RemovalRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(19)
		selectedAssert(t, &v)
		v.bodySeNBAdditionRequest = new(SeNBAdditionRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(20)
		selectedAssert(t, &v)
		v.bodySeNBReconfigurationComplete = new(SeNBReconfigurationComplete)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(21)
		selectedAssert(t, &v)
		v.bodySeNBModificationRequest = new(SeNBModificationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(22)
		selectedAssert(t, &v)
		v.bodySeNBModificationRequired = new(SeNBModificationRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(23)
		selectedAssert(t, &v)
		v.bodySeNBReleaseRequest = new(SeNBReleaseRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(24)
		selectedAssert(t, &v)
		v.bodySeNBReleaseRequired = new(SeNBReleaseRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(25)
		selectedAssert(t, &v)
		v.bodySeNBCounterCheckRequest = new(SeNBCounterCheckRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(26)
		selectedAssert(t, &v)
		v.bodyRetrieveUEContextRequest = new(RetrieveUEContextRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(27)
		selectedAssert(t, &v)
		v.bodySgNBAdditionRequest = new(SgNBAdditionRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(28)
		selectedAssert(t, &v)
		v.bodySgNBReconfigurationComplete = new(SgNBReconfigurationComplete)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(29)
		selectedAssert(t, &v)
		v.bodySgNBModificationRequest = new(SgNBModificationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(30)
		selectedAssert(t, &v)
		v.bodySgNBModificationRequired = new(SgNBModificationRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(31)
		selectedAssert(t, &v)
		v.bodySgNBReleaseRequest = new(SgNBReleaseRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(32)
		selectedAssert(t, &v)
		v.bodySgNBReleaseRequired = new(SgNBReleaseRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(33)
		selectedAssert(t, &v)
		v.bodySgNBCounterCheckRequest = new(SgNBCounterCheckRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(34)
		selectedAssert(t, &v)
		v.bodySgNBChangeRequired = new(SgNBChangeRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(35)
		selectedAssert(t, &v)
		v.bodyRRCTransfer = new(RRCTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(36)
		selectedAssert(t, &v)
		v.bodyENDCX2SetupRequest = new(ENDCX2SetupRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(37)
		selectedAssert(t, &v)
		v.bodyENDCConfigurationUpdate = new(ENDCConfigurationUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(38)
		selectedAssert(t, &v)
		v.bodySecondaryRATDataUsageReport = new(SecondaryRATDataUsageReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(39)
		selectedAssert(t, &v)
		v.bodyENDCCellActivationRequest = new(ENDCCellActivationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(40)
		selectedAssert(t, &v)
		v.bodyENDCPartialResetRequired = new(ENDCPartialResetRequired)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(41)
		selectedAssert(t, &v)
		v.bodyEUTRANRCellResourceCoordinationRequest = new(EUTRANRCellResourceCoordinationRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(42)
		selectedAssert(t, &v)
		v.bodySgNBActivityNotification = new(SgNBActivityNotification)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(43)
		selectedAssert(t, &v)
		v.bodyENDCX2RemovalRequest = new(ENDCX2RemovalRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(44)
		selectedAssert(t, &v)
		v.bodyDataForwardingAddressIndication = new(DataForwardingAddressIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(45)
		selectedAssert(t, &v)
		v.bodyGNBStatusIndication = new(GNBStatusIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(46)
		selectedAssert(t, &v)
		v.bodyDeactivateTrace = new(DeactivateTrace)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(47)
		selectedAssert(t, &v)
		v.bodyTraceStart = new(TraceStart)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(48)
		selectedAssert(t, &v)
		v.bodyENDCConfigurationTransfer = new(ENDCConfigurationTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(49)
		selectedAssert(t, &v)
		v.bodyHandoverSuccess = new(HandoverSuccess)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(50)
		selectedAssert(t, &v)
		v.bodyConditionalHandoverCancel = new(ConditionalHandoverCancel)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(51)
		selectedAssert(t, &v)
		v.bodyEarlyStatusTransfer = new(EarlyStatusTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(52)
		selectedAssert(t, &v)
		v.bodyCellTrafficTrace = new(CellTrafficTrace)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(53)
		selectedAssert(t, &v)
		v.bodyENDCResourceStatusUpdate = new(ENDCResourceStatusUpdate)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(54)
		selectedAssert(t, &v)
		v.bodyENDCResourceStatusRequest = new(ENDCResourceStatusRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(55)
		selectedAssert(t, &v)
		v.bodyF1CTrafficTransfer = new(F1CTrafficTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(56)
		selectedAssert(t, &v)
		v.bodyUERadioCapabilityIDMappingRequest = new(UERadioCapabilityIDMappingRequest)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(57)
		selectedAssert(t, &v)
		v.bodyAccessAndMobilityIndication = new(AccessAndMobilityIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(59)
		selectedAssert(t, &v)
		v.bodyCPCCancel = new(CPCCancel)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(60)
		selectedAssert(t, &v)
		v.bodyRachIndication = new(RachIndication)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(61)
		selectedAssert(t, &v)
		v.bodySCGFailureInformationReport = new(SCGFailureInformationReport)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	{
		v := InitiatingValue{}
		v.code = s00.ProcedureCode(62)
		selectedAssert(t, &v)
		v.bodySCGFailureTransfer = new(SCGFailureTransfer)
		selectedAssert(t, &v)
		v.isOpaque = true
		v.opaque = opaque
		selectedAssert(t, &v)
	}
	t.Logf("union InitiatingValue: 62 synthetic rows")
}
