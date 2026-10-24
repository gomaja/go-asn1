package lppa

import (
	q13 "errors"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	bridge3 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	bridge4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	bridge2 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q24 "math/big"
	q11 "strings"
	q8 "testing"
)

func requireSelectorIssue(t *q8.T, report ValidationReport, id ProtocolIEID) {
	t.Helper()
	for _, issue := range report.Issues {
		if issue.Code == ValueIDMismatch && issue.IEID == id && issue.Severity == ValidationSeverityError && issue.HasIEID && q11.HasSuffix(string(issue.Location.Path), ".id") && issue.Rule.Document == "3GPP TS 36.455" && issue.Rule.Clause == "§10" {
			return
		}
	}
	t.Errorf("missing located selector error for ID %d: %+v", id, report)
}
func requireSelectorEncodeError(t *q8.T, err error) {
	t.Helper()
	var located *q12.DecodePathError
	if !q13.As(err, &located) || !q11.Contains(located.Path, "Id") || !q13.Is(err, q14.ErrInvalidValue) {
		t.Errorf("encoder accepted mismatched selector or lost location: %v", err)
	}
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 bind each value to its outer @id.
func TestFieldIDMustMatchTypedValue(t *q8.T) {
	table := ErrorIndicationIEs()
	field := errorIndicationIEFieldConsistencyMust(table.CriticalityDiagnostics().New(CriticalityDiagnostics{}))
	field.Id = table.Cause().Info().ID
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	message := InitiatingMessage{ProcedureCode: ErrorIndicationProcedure().Info().Code, Criticality: CriticalityIgnore, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*bridge0.BridgeInitiatingValueFieldCode(&sealed) = ErrorIndicationProcedure().Info().Code
		*bridge0.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	report, err := ValidateMessage(&pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, field.Id)
	_, err = NewErrorIndication(body.ProtocolIEs)
	var build *BuildError
	if !q13.As(err, &build) {
		t.Errorf("builder accepted mismatched selector: %v", err)
	}
	_, err = ErrorIndicationProcedure().Initiating().Build(body, 7)
	if !q13.As(err, &build) {
		t.Errorf("procedure builder accepted mismatched selector: %v", err)
	}
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
	_, err = pdu.MarshalAPER()
	requireSelectorEncodeError(t, err)
	bb := q14.NewBitBuffer()
	requireSelectorEncodeError(t, bridge1.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Errorf("selector refusal emitted %d bits", bb.BitPos())
	}
	// An opaque value must not be retagged to masquerade as a known value.
	opaque := errorIndicationIEFieldConsistencyMust(table.NewOpaque(65532, CriticalityIgnore, []byte{0}))
	opaque.Id = table.Cause().Info().ID
	body.ProtocolIEs[0] = opaque
	report, err = ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, opaque.Id)
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
	// Retagging to another unknown ID also changes the original selector.
	opaque.Id = 65531
	body.ProtocolIEs[0] = opaque
	report, err = ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, opaque.Id)
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
}
func TestExtensionIDMustMatchTypedValue(t *q8.T) {
	table := ResultNRItemExtIEs()
	field := resultNRItemExtIEsExtFieldConsistencyMust(table.ResultsPerSSBIndexList().New(ResultsPerSSBIndexList{{}}))
	valid := ResultNRItem{IEExtensions: ResultNRItemExtIEsExtContainer{field}}
	validReport := ValidationReport{Complete: true}
	bridge2.BridgeWalkValidationResultNRItem(&valid, &validReport, "ResultNRItem", false)
	if len(validReport.Issues) != 0 {
		t.Fatalf("matching extension selector refused: %+v", validReport)
	}
	if _, err := valid.MarshalAPER(); err != nil {
		t.Fatal(err)
	}
	field.Id = table.NRCGI().Info().ID
	item := ResultNRItem{IEExtensions: ResultNRItemExtIEsExtContainer{field}}
	report := ValidationReport{Complete: true}
	bridge2.BridgeWalkValidationResultNRItem(&item, &report, "ResultNRItem", false)
	requireSelectorIssue(t, report, field.Id)
	_, err := item.MarshalAPER()
	requireSelectorEncodeError(t, err)
	bb := q14.NewBitBuffer()
	requireSelectorEncodeError(t, bridge3.BridgeResultNRItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Errorf("selector refusal emitted %d bits", bb.BitPos())
	}
	// Reach the extension through a procedure body and its checked builder.
	result := InterRATMeasurementResult{{Choice: InterRATMeasuredResultsValueChoiceResultNR, ResultNR: ResultNR{item}}}
	root := ECIDMeasurementInitiationResponseIEs()
	// Assemble the root row directly to exercise validation independently of
	// the binding's complete-value encoding check.
	fields := ECIDMeasurementInitiationResponseIEContainer{eCIDMeasurementInitiationResponseIEFieldConsistencyMust(root.ESMLCUEMeasurementID().New(q24.NewInt(1))), eCIDMeasurementInitiationResponseIEFieldConsistencyMust(root.ENBUEMeasurementID().New(q24.NewInt(2))), {Id: root.InterRATMeasurementResult().Info().ID, Criticality: CriticalityIgnore, Value: func() ECIDMeasurementInitiationResponseIEValue {
		sealed := ECIDMeasurementInitiationResponseIEValue{}
		*bridge4.BridgeECIDMeasurementInitiationResponseIEValueFieldId(&sealed) = root.InterRATMeasurementResult().Info().ID
		*bridge4.BridgeECIDMeasurementInitiationResponseIEValueFieldRowInterRATMeasurementResult(&sealed) = &result
		return sealed
	}()}}
	body := ECIDMeasurementInitiationResponse{ProtocolIEs: fields}
	report, err = ValidateECIDMeasurementInitiationResponse(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, field.Id)
	_, err = NewECIDMeasurementInitiationResponse(fields)
	var build *BuildError
	if !q13.As(err, &build) {
		t.Errorf("builder accepted mismatched extension selector: %v", err)
	}
}
