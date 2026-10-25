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
