package lppa

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
	"strings"
	"testing"
)

func requireSelectorIssue(t *testing.T, report ValidationReport, id ProtocolIEID) {
	t.Helper()
	for _, issue := range report.Issues {
		if issue.Code == ValueIDMismatch && issue.IEID == id && issue.Severity == ValidationSeverityError && issue.HasIEID && strings.HasSuffix(string(issue.Location.Path), ".id") && issue.Rule.Document == "3GPP TS 36.455" && issue.Rule.Clause == "§10" {
			return
		}
	}
	t.Errorf("missing located selector error for ID %d: %+v", id, report)
}
func requireSelectorEncodeError(t *testing.T, err error) {
	t.Helper()
	var located *runtime.DecodePathError
	if !errors.As(err, &located) || !strings.Contains(located.Path, "Id") || !errors.Is(err, aper.ErrInvalidValue) {
		t.Errorf("encoder accepted mismatched selector or lost location: %v", err)
	}
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 bind each value to its outer @id.
func TestFieldIDMustMatchTypedValue(t *testing.T) {
	table := ErrorIndicationIEs()
	field := errorIndicationIEFieldConsistencyMust(table.CriticalityDiagnostics().New(CriticalityDiagnostics{}))
	field.Id = table.Cause().Info().ID
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	message := InitiatingMessage{ProcedureCode: ErrorIndicationProcedure().Info().Code, Criticality: CriticalityIgnore, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = ErrorIndicationProcedure().Info().Code
		*s21.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
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
	if !errors.As(err, &build) {
		t.Errorf("builder accepted mismatched selector: %v", err)
	}
	_, err = ErrorIndicationProcedure().Initiating().Build(body, 7)
	if !errors.As(err, &build) {
		t.Errorf("procedure builder accepted mismatched selector: %v", err)
	}
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
	_, err = pdu.MarshalAPER()
	requireSelectorEncodeError(t, err)
	bb := aper.NewBitBuffer()
	requireSelectorEncodeError(t, s10.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, bb))
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
func TestExtensionIDMustMatchTypedValue(t *testing.T) {
	table := ResultNRItemExtIEs()
	field := resultNRItemExtIEsExtFieldConsistencyMust(table.ResultsPerSSBIndexList().New(ResultsPerSSBIndexList{{}}))
	valid := ResultNRItem{IEExtensions: ResultNRItemExtIEsExtContainer{field}}
	validReport := ValidationReport{Complete: true}
	s23.BridgeWalkValidationResultNRItem(&valid, &validReport, "ResultNRItem", false)
	if len(validReport.Issues) != 0 {
		t.Fatalf("matching extension selector refused: %+v", validReport)
	}
	if _, err := valid.MarshalAPER(); err != nil {
		t.Fatal(err)
	}
	field.Id = table.NRCGI().Info().ID
	item := ResultNRItem{IEExtensions: ResultNRItemExtIEsExtContainer{field}}
	report := ValidationReport{Complete: true}
	s23.BridgeWalkValidationResultNRItem(&item, &report, "ResultNRItem", false)
	requireSelectorIssue(t, report, field.Id)
	_, err := item.MarshalAPER()
	requireSelectorEncodeError(t, err)
	bb := aper.NewBitBuffer()
	requireSelectorEncodeError(t, s19.BridgeResultNRItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Errorf("selector refusal emitted %d bits", bb.BitPos())
	}
	// Reach the extension through a procedure body and its checked builder.
	result := InterRATMeasurementResult{{Choice: InterRATMeasuredResultsValueChoiceResultNR, ResultNR: ResultNR{item}}}
	root := ECIDMeasurementInitiationResponseIEs()
	// Assemble the root row directly to exercise validation independently of
	// the binding's complete-value encoding check.
	fields := ECIDMeasurementInitiationResponseIEContainer{eCIDMeasurementInitiationResponseIEFieldConsistencyMust(root.ESMLCUEMeasurementID().New(big.NewInt(1))), eCIDMeasurementInitiationResponseIEFieldConsistencyMust(root.ENBUEMeasurementID().New(big.NewInt(2))), {Id: root.InterRATMeasurementResult().Info().ID, Criticality: CriticalityIgnore, Value: func() ECIDMeasurementInitiationResponseIEValue {
		sealed := ECIDMeasurementInitiationResponseIEValue{}
		*s22.BridgeECIDMeasurementInitiationResponseIEValueFieldId(&sealed) = root.InterRATMeasurementResult().Info().ID
		*s22.BridgeECIDMeasurementInitiationResponseIEValueFieldRowInterRATMeasurementResult(&sealed) = &result
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
	if !errors.As(err, &build) {
		t.Errorf("builder accepted mismatched extension selector: %v", err)
	}
}
