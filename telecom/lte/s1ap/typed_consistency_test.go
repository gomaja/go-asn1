// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

func requireSelectorIssue(t *testing.T, report s25.ValidationReport, id s00.ProtocolIEID) {
	t.Helper()
	for _, issue := range report.Issues {
		if issue.Code == s00.ValueIDMismatch && issue.IEID == id && issue.Severity == s00.ValidationSeverityError && issue.HasIEID && strings.HasSuffix(string(issue.Location.Path), ".id") && issue.Rule.Document == "3GPP TS 36.413" && issue.Rule.Clause == "§10" {
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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 bind each value to its outer @id.
func TestFieldIDMustMatchTypedValue(t *testing.T) {
	table := s36.ErrorIndicationIEs()
	field := errorIndicationIEFieldConsistencyMust(table.CriticalityDiagnostics().New(s26.CriticalityDiagnostics{}))
	field.Id = table.Cause().Info().ID
	body := s36.ErrorIndication{ProtocolIEs: s36.ErrorIndicationIEContainer{field}}
	message := s65.InitiatingMessage{ProcedureCode: s65.ErrorIndicationProcedure().Info().Code, Criticality: s00.CriticalityIgnore, Value: func() s65.InitiatingValue {
		sealed := s65.InitiatingValue{}
		*s65.BridgeInitiatingValueFieldCode(&sealed) = s65.ErrorIndicationProcedure().Info().Code
		*s65.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := s66.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	report, err := s67.ValidateMessage(&pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, field.Id)
	_, err = s62.NewErrorIndication(body.ProtocolIEs)
	var build *s25.BuildError
	if !errors.As(err, &build) {
		t.Errorf("builder accepted mismatched selector: %v", err)
	}
	_, err = s65.ErrorIndicationProcedure().Initiating().Build(body)
	if !errors.As(err, &build) {
		t.Errorf("procedure builder accepted mismatched selector: %v", err)
	}
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
	_, err = pdu.MarshalAPER()
	requireSelectorEncodeError(t, err)
	bb := aper.NewBitBuffer()
	requireSelectorEncodeError(t, s36.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Errorf("selector refusal emitted %d bits", bb.BitPos())
	}
	// An opaque value must not be retagged to masquerade as a known value.
	opaque := errorIndicationIEFieldConsistencyMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	opaque.Id = table.Cause().Info().ID
	body.ProtocolIEs[0] = opaque
	report, err = s62.ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, opaque.Id)
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
	// Retagging to another unknown ID also changes the original selector.
	opaque.Id = 65531
	body.ProtocolIEs[0] = opaque
	report, err = s62.ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, opaque.Id)
	_, err = body.MarshalAPER()
	requireSelectorEncodeError(t, err)
}
func TestExtensionIDMustMatchTypedValue(t *testing.T) {
	table := s37.ERABInformationListItemExtIEs()
	field := eRABInformationListItemExtIEsExtFieldConsistencyMust(table.DAPSRequestInfo().New(s17.DAPSRequestInfo{}))
	field.Id = 65532
	report := s25.ValidationReport{Complete: true}
	// This source container is itself a transparent-container value, so the
	// standalone source walk exercises its extension boundary directly.
	item := s37.ERABInformationListItem{IEExtensions: s37.ERABInformationListItemExtIEsExtContainer{field}}
	s62.BridgeWalkValidationERABInformationListItem(&item, &report, "ERABInformationListItem", false)
	requireSelectorIssue(t, report, field.Id)
	for _, fresh := range []bool{false, true} {
		bb := aper.NewBitBuffer()
		requireSelectorEncodeError(t, s37.BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh))
		if bb.BitsWritten() != 0 {
			t.Fatal("extension refusal wrote bits")
		}
	}
	// Reach an opaque extension mismatch through a complete source procedure.
	ext := criticalityDiagnosticsExtIEsExtFieldConsistencyMust(s09.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	diagnostics := s26.CriticalityDiagnostics{IEExtensions: s09.CriticalityDiagnosticsExtIEsExtContainer{ext}}
	root := s36.ErrorIndicationIEs()
	outer := errorIndicationIEFieldConsistencyMust(root.CriticalityDiagnostics().New(diagnostics))
	value, _ := outer.Value.AsCriticalityDiagnostics()
	value.IEExtensions[0].Id = 65531
	body := s36.ErrorIndication{ProtocolIEs: s36.ErrorIndicationIEContainer{outer}}
	report, err := s62.ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, 65531)
	var build *s25.BuildError
	if _, err := s62.NewErrorIndication(body.ProtocolIEs); !errors.As(err, &build) {
		t.Fatalf("nested builder refusal=%v", err)
	}
	message := s65.InitiatingMessage{ProcedureCode: s65.ErrorIndicationProcedure().Info().Code, Criticality: s00.CriticalityIgnore, Value: func() s65.InitiatingValue {
		sealed := s65.InitiatingValue{}
		*s65.BridgeInitiatingValueFieldCode(&sealed) = s65.ErrorIndicationProcedure().Info().Code
		*s65.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := s66.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	report, err = s67.ValidateMessage(&pdu)
	if err != nil {
		t.Fatal(err)
	}
	requireSelectorIssue(t, report, 65531)
}
func TestIESelectorBoundaryReplayAndFresh(t *testing.T) {
	table := s36.ErrorIndicationIEs()
	codec := s36.ErrorIndicationIEValueIEFieldTableCodec(table.Table())
	known := errorIndicationIEFieldConsistencyMust(table.CriticalityDiagnostics().New(s26.CriticalityDiagnostics{}))
	opaque := errorIndicationIEFieldConsistencyMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	for _, tc := range []struct {
		name  string
		field s36.ErrorIndicationIEField
	}{{"typed", known}, {"opaque", opaque}} {
		for _, origin := range []string{"built", "decoded", "literal"} {
			t.Run(tc.name+"/"+origin, func(t *testing.T) {
				field := tc.field
				wire := sliceByteConsistencyMust(codec.EncodeAPER(errorIndicationIEFieldAPERValueConsistencyMust(codec.New(field))))
				if origin == "decoded" {
					owned, _, err := codec.DecodeAPER(wire)
					if err != nil {
						t.Fatal(err)
					}
					field = owned.Value
				}
				if origin == "literal" {
					field = s36.ErrorIndicationIEField{Id: field.Id, Criticality: field.Criticality, Value: field.Value}
				}
				for _, wrong := range []s00.ProtocolIEID{2, 65531} {
					field.Id = wrong
					for _, fresh := range []bool{false, true} {
						bb := aper.NewBitBuffer()
						requireSelectorEncodeError(t, s36.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh))
						if bb.BitPos() != 0 {
							t.Fatal("IE refusal wrote bits")
						}
						owned := s36.ErrorIndicationIEFieldAPERValue{Value: field}
						var options []aper.EncodeOption
						if fresh {
							options = []aper.EncodeOption{aper.WithoutReplay()}
							owned = owned.WithoutReplay()
						}
						_, err := codec.EncodeAPER(owned, options...)
						requireSelectorEncodeError(t, err)
					}
				}
			})
		}
	}
}
func TestExtensionSelectorBoundaryReplayAndFresh(t *testing.T) {
	table := s37.ERABInformationListItemExtIEs()
	codec := s37.ERABInformationListItemExtIEsValueExtensionFieldTableCodec(table.Table())
	known := eRABInformationListItemExtIEsExtFieldConsistencyMust(table.DAPSRequestInfo().New(s17.DAPSRequestInfo{}))
	opaque := eRABInformationListItemExtIEsExtFieldConsistencyMust(table.NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	for _, tc := range []struct {
		name  string
		field s37.ERABInformationListItemExtIEsExtField
	}{{"typed", known}, {"opaque", opaque}} {
		for _, origin := range []string{"built", "decoded", "literal"} {
			t.Run(tc.name+"/"+origin, func(t *testing.T) {
				field := tc.field
				wire := sliceByteConsistencyMust(codec.EncodeAPER(eRABInformationListItemExtIEsExtFieldAPERValueConsistencyMust(codec.New(field))))
				if origin == "decoded" {
					owned, _, err := codec.DecodeAPER(wire)
					if err != nil {
						t.Fatal(err)
					}
					field = owned.Value
				}
				if origin == "literal" {
					field = s37.ERABInformationListItemExtIEsExtField{Id: field.Id, Criticality: field.Criticality, ExtensionValue: field.ExtensionValue}
				}
				for _, wrong := range []s00.ProtocolExtensionID{318, 65531} {
					field.Id = wrong
					for _, fresh := range []bool{false, true} {
						bb := aper.NewBitBuffer()
						requireSelectorEncodeError(t, s37.BridgeERABInformationListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh))
						if bb.BitPos() != 0 {
							t.Fatal("extension refusal wrote bits")
						}
						owned := s37.ERABInformationListItemExtIEsExtFieldAPERValue{Value: field}
						var options []aper.EncodeOption
						if fresh {
							options = []aper.EncodeOption{aper.WithoutReplay()}
							owned = owned.WithoutReplay()
						}
						_, err := codec.EncodeAPER(owned, options...)
						requireSelectorEncodeError(t, err)
					}
				}
			})
		}
	}
}
