package lppa

import (
	"bytes"
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
	"testing"
)

func TestTypedCodecPropagatesDecodeLimits(t *testing.T) {
	codec := MeasurementIDCodec()
	value, err := codec.New(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := codec.EncodeAPER(value)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = codec.DecodeAPER(wire, aper.WithLimits(aper.Limits{MaxWork: 1}))
	if !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("decode ignored work limit: %v", err)
	}
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("typed codec replay=%x err=%v", replay, err)
	}
}

// TS 36.455 V19.0.0 §§9.3.3–9.3.5: both object-set levels select one
// source type, and the descriptor binds the procedure and transaction ID.
func TestTypedBindingsBuildNestedIEs(t *testing.T) {
	inner, err := MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(MeasurementQuantitiesItem{})
	if err != nil {
		t.Fatal(err)
	}
	table := ECIDMeasurementInitiationRequestIEs()
	id, err := table.ESMLCUEMeasurementID().New(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	report, err := table.ReportCharacteristics().New(ReportCharacteristicsOnDemand)
	if err != nil {
		t.Fatal(err)
	}
	quantities, err := table.MeasurementQuantities().New(MeasurementQuantities{inner})
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewECIDMeasurementInitiationRequest(ECIDMeasurementInitiationRequestIEContainer{id, report, quantities})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := ECIDMeasurementInitiationProcedure().Initiating().Build(body, LPPATransactionID(7))
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := NewLPPAPDUInitiatingMessage(outcome)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded LPPAPDU
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	gotBody, ok := decoded.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	if !ok || len(gotBody.ProtocolIEs) != 3 {
		t.Fatalf("typed body = %+v", gotBody)
	}
	gotID, ok := table.ESMLCUEMeasurementID().Get(&gotBody.ProtocolIEs[0])
	if !ok || gotID == nil || *gotID == nil || (*gotID).Int64() != 1 {
		t.Fatalf("typed ID = %v, ok=%v", gotID, ok)
	}
	gotList, ok := table.MeasurementQuantities().Get(&gotBody.ProtocolIEs[2])
	if !ok || len(*gotList) != 1 {
		t.Fatalf("typed list = %v, ok=%v", gotList, ok)
	}
	nested, ok := MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().Get(&(*gotList)[0])
	if !ok || nested == nil {
		t.Fatalf("typed nested IE = %v, ok=%v", nested, ok)
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay=%x err=%v want %x", replay, err, wire)
	}
	validation, err := ValidateMessage(&decoded)
	if err != nil || len(validation.Issues) != 0 {
		t.Fatalf("validation=%+v err=%v", validation, err)
	}
	(*gotID).SetInt64(2)
	edited, err := decoded.MarshalAPER()
	if err != nil || bytes.Equal(edited, wire) {
		t.Fatalf("edited wire=%x err=%v", edited, err)
	}
	var changed LPPAPDU
	if _, err := changed.UnmarshalAPER(edited); err != nil {
		t.Fatal(err)
	}
	changedBody, ok := changed.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	if !ok {
		t.Fatal("edited procedure lost typed body")
	}
	changedID, ok := table.ESMLCUEMeasurementID().Get(&changedBody.ProtocolIEs[0])
	if !ok || changedID == nil || *changedID == nil || (*changedID).Int64() != 2 {
		t.Fatalf("edited ID = %v, ok=%v", changedID, ok)
	}
	(*gotID).SetInt64(1)
	restored, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(restored, wire) {
		t.Fatalf("restored wire=%x err=%v", restored, err)
	}
}
func TestUnknownIEKeepsOriginAndBytes(t *testing.T) {
	table := ECIDMeasurementInitiationRequestIEs()
	future, err := table.NewOpaque(65532, CriticalityIgnore, []byte{0x12, 0x34})
	if err != nil {
		t.Fatal(err)
	}
	body := ECIDMeasurementInitiationRequest{ProtocolIEs: ECIDMeasurementInitiationRequestIEContainer{future}}
	outcome := InitiatingMessage{ProcedureCode: 2, Criticality: CriticalityReject, LppatransactionID: 7, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = 2
		*s21.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &outcome}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded LPPAPDU
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	gotBody, ok := decoded.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	if !ok || len(gotBody.ProtocolIEs) != 1 {
		t.Fatalf("body=%+v", gotBody)
	}
	opaque, ok := gotBody.ProtocolIEs[0].Value.Opaque()
	if !ok {
		t.Fatal("unknown IE was not opaque")
	}
	if !bytes.Equal(opaque.Bytes(), []byte{0x12, 0x34}) || opaque.Origin().Reason != aper.UnknownSelector || !opaque.Origin().HasWireLocation || len(opaque.Origin().Location.Spans) != 1 || opaque.Origin().Location.Path != "ProtocolIEField.Value" {
		t.Fatalf("opaque=%x origin=%+v", opaque.Bytes(), opaque.Origin())
	}
	wire2, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(wire2, wire) {
		t.Fatalf("replay=%x err=%v", wire2, err)
	}
	report, err := ValidateMessage(&decoded)
	if err != nil || len(report.Issues) == 0 || report.Issues[0].Severity != ValidationSeverityUnrecognized {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}
func TestMalformedKnownIEIsAnError(t *testing.T) {
	opaque := aper.NewOpaqueOpenType([]byte{0xff})
	malformed := func() ECIDMeasurementInitiationRequestIEValue {
		sealed := ECIDMeasurementInitiationRequestIEValue{}
		*s21.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = 2
		*s21.BridgeECIDMeasurementInitiationRequestIEValueFieldIsOpaque(&sealed) = true
		*s21.BridgeECIDMeasurementInitiationRequestIEValueFieldOpaque(&sealed) = &opaque
		return sealed
	}()
	body := ECIDMeasurementInitiationRequest{ProtocolIEs: ECIDMeasurementInitiationRequestIEContainer{{Id: 2, Criticality: CriticalityReject, Value: malformed}}}
	outcome := InitiatingMessage{ProcedureCode: 2, Criticality: CriticalityReject, LppatransactionID: 7, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = 2
		*s21.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &outcome}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded LPPAPDU
	if _, err := decoded.UnmarshalAPER(wire); err == nil {
		t.Fatal("malformed known IE decoded as opaque")
	}
}
func TestNestedIEValidation(t *testing.T) {
	inner, err := MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().New(MeasurementQuantitiesItem{})
	if err != nil {
		t.Fatal(err)
	}
	inner.Criticality = CriticalityIgnore
	outer, err := ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().New(MeasurementQuantities{inner})
	if err != nil {
		t.Fatal(err)
	}
	body := ECIDMeasurementInitiationRequest{ProtocolIEs: ECIDMeasurementInitiationRequestIEContainer{outer}}
	report, err := ValidateECIDMeasurementInitiationRequest(&body)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range report.Issues {
		if issue.Code == WrongCriticality && issue.IEID == 11 {
			found = true
		}
	}
	if !found {
		t.Fatalf("nested criticality missing: %+v", report.Issues)
	}
}
