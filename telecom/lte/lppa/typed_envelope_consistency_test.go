package lppa

import (
	q23 "bytes"
	q14 "errors"
	bridge3 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	bridge2 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"

	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q20 "math/big"
	q12 "strings"
	q8 "testing"
)

func requireEnvelopeMismatch(t *q8.T, pdu *LPPAPDU) {
	t.Helper()
	report, err := ValidateMessage(pdu)
	if err != nil {
		t.Errorf("validation returned an error instead of a selector issue: %v", err)
		return
	}
	for _, issue := range report.Issues {
		if issue.Code == ValueIDMismatch && issue.Severity == ValidationSeverityError && !issue.HasIEID && q12.HasSuffix(string(issue.Location.Path), ".procedureCode") && issue.Rule.Document == "3GPP TS 36.455" && issue.Rule.Clause == "§10" && len(issue.RelatedRules) != 0 {
			return
		}
	}
	t.Errorf("missing envelope selector issue: %+v", report)
}
func requireEnvelopeEncodeError(t *q8.T, err error) {
	t.Helper()
	var located *q13.DecodePathError
	if !q14.Is(err, q15.ErrInvalidValue) || !q14.As(err, &located) || !q12.Contains(located.Path, "ProcedureCode") {
		t.Errorf("missing located invalid-value refusal: %v", err)
	}
}
func requireEnvelopeBuildError(t *q8.T, err error) {
	t.Helper()
	var build *BuildError
	if !q14.As(err, &build) {
		t.Errorf("builder accepted mismatched envelope or lost structural error: %v", err)
		return
	}
	if len(build.Issues) != 1 || build.Issues[0].Code != ValueIDMismatch || !q12.HasSuffix(string(build.Issues[0].Location.Path), ".procedureCode") {
		t.Errorf("wrong builder issue: %+v", build.Issues)
	}
}
func envelopeCode(p *LPPAPDU) *ProcedureCode {
	switch p.Choice {
	case LPPAPDUChoiceInitiatingMessage:
		return &p.InitiatingMessage.ProcedureCode
	case LPPAPDUChoiceSuccessfulOutcome:
		return &p.SuccessfulOutcome.ProcedureCode
	default:
		return &p.UnsuccessfulOutcome.ProcedureCode
	}
}
func encodeEnvelope(p *LPPAPDU, bb *q15.BitBuffer, fresh bool) error {
	switch p.Choice {
	case LPPAPDUChoiceInitiatingMessage:
		return bridge0.BridgeInitiatingMessageMethodMarshalAPERTo(p.InitiatingMessage, bb, fresh)
	case LPPAPDUChoiceSuccessfulOutcome:
		return bridge1.BridgeSuccessfulOutcomeMethodMarshalAPERTo(p.SuccessfulOutcome, bb, fresh)
	default:
		return bridge2.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(p.UnsuccessfulOutcome, bb, fresh)
	}
}
func marshalEnvelope(p *LPPAPDU, options ...q15.EncodeOption) ([]byte, error) {
	switch p.Choice {
	case LPPAPDUChoiceInitiatingMessage:
		return p.InitiatingMessage.MarshalAPER(options...)
	case LPPAPDUChoiceSuccessfulOutcome:
		return p.SuccessfulOutcome.MarshalAPER(options...)
	default:
		return p.UnsuccessfulOutcome.MarshalAPER(options...)
	}
}

// TS 36.455 V19.0.0 §§9.3.3,9.3.8 bind every outcome's value to @procedureCode.
func TestEnvelopeProcedureCodeMustMatchValue(t *q8.T) {
	responseTable := ECIDMeasurementInitiationResponseIEs()
	response := eCIDMeasurementInitiationResponseEnvelopeMust(NewECIDMeasurementInitiationResponse(ECIDMeasurementInitiationResponseIEContainer{eCIDMeasurementInitiationResponseIEFieldEnvelopeMust(responseTable.ESMLCUEMeasurementID().New(q20.NewInt(1))), eCIDMeasurementInitiationResponseIEFieldEnvelopeMust(responseTable.ENBUEMeasurementID().New(q20.NewInt(2)))}))
	failureTable := ECIDMeasurementInitiationFailureIEs()
	cause := causeEnvelopeMust(NewCauseProtocol(CauseProtocolSemanticError))
	failure := eCIDMeasurementInitiationFailureEnvelopeMust(NewECIDMeasurementInitiationFailure(ECIDMeasurementInitiationFailureIEContainer{eCIDMeasurementInitiationFailureIEFieldEnvelopeMust(failureTable.ESMLCUEMeasurementID().New(q20.NewInt(1))), eCIDMeasurementInitiationFailureIEFieldEnvelopeMust(failureTable.Cause().New(cause))}))
	initiating := initiatingMessageEnvelopeMust(ErrorIndicationProcedure().Initiating().Build(errorIndicationEnvelopeMust(NewErrorIndication(nil)), 7))
	successful := successfulOutcomeEnvelopeMust(ECIDMeasurementInitiationProcedure().Successful().Build(response, 7))
	unsuccessful := unsuccessfulOutcomeEnvelopeMust(ECIDMeasurementInitiationProcedure().Unsuccessful().Build(failure, 7))
	cases := []struct {
		name string
		pdu  LPPAPDU
	}{
		{"initiating", LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &initiating}},
		{"successful", LPPAPDU{Choice: LPPAPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &successful}},
		{"unsuccessful", LPPAPDU{Choice: LPPAPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &unsuccessful}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *q8.T) {
			knownWire := sliceByteEnvelopeMust(tc.pdu.MarshalAPER())
			opaque := tc.pdu
			switch opaque.Choice {
			case LPPAPDUChoiceInitiatingMessage:
				v := initiatingMessageEnvelopeMust(NewOpaqueInitiatingMessage(250, CriticalityIgnore, 7, []byte{0x81}))
				opaque.InitiatingMessage = &v
			case LPPAPDUChoiceSuccessfulOutcome:
				v := successfulOutcomeEnvelopeMust(NewOpaqueSuccessfulOutcome(250, CriticalityIgnore, 7, []byte{0x81}))
				opaque.SuccessfulOutcome = &v
			default:
				v := unsuccessfulOutcomeEnvelopeMust(NewOpaqueUnsuccessfulOutcome(250, CriticalityIgnore, 7, []byte{0x81}))
				opaque.UnsuccessfulOutcome = &v
			}
			for _, valueCase := range []struct {
				name string
				pdu  LPPAPDU
				wire []byte
			}{{"typed", tc.pdu, knownWire}, {"opaque", opaque, sliceByteEnvelopeMust(opaque.MarshalAPER())}} {
				t.Run(valueCase.name, func(t *q8.T) {
					for _, origin := range []string{"built", "decoded", "literal"} {
						t.Run(origin, func(t *q8.T) {
							value := valueCase.pdu
							if origin == "decoded" {
								value = LPPAPDU{}
								if _, err := value.UnmarshalAPER(valueCase.wire); err != nil {
									t.Fatal(err)
								}
							}
							// A literal can copy a closed value while independently choosing its outer code.
							switch value.Choice {
							case LPPAPDUChoiceInitiatingMessage:
								v := *value.InitiatingMessage
								value.InitiatingMessage = &InitiatingMessage{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, LppatransactionID: v.LppatransactionID, Value: v.Value}
							case LPPAPDUChoiceSuccessfulOutcome:
								v := *value.SuccessfulOutcome
								value.SuccessfulOutcome = &SuccessfulOutcome{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, LppatransactionID: v.LppatransactionID, Value: v.Value}
							default:
								v := *value.UnsuccessfulOutcome
								value.UnsuccessfulOutcome = &UnsuccessfulOutcome{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, LppatransactionID: v.LppatransactionID, Value: v.Value}
							}
							if origin == "decoded" {
								if _, err := value.UnmarshalAPER(valueCase.wire); err != nil {
									t.Fatal(err)
								}
							}
							replay := sliceByteEnvelopeMust(value.MarshalAPER())
							if !q23.Equal(replay, valueCase.wire) {
								t.Fatal("matching selector changed replay")
							}
							original := *envelopeCode(&value)
							for _, wrong := range []ProcedureCode{1, 249} {
								*envelopeCode(&value) = wrong
								requireEnvelopeMismatch(t, &value)
								switch value.Choice {
								case LPPAPDUChoiceInitiatingMessage:
									_, err := NewLPPAPDUInitiatingMessage(*value.InitiatingMessage)
									requireEnvelopeBuildError(t, err)
								case LPPAPDUChoiceSuccessfulOutcome:
									_, err := NewLPPAPDUSuccessfulOutcome(*value.SuccessfulOutcome)
									requireEnvelopeBuildError(t, err)
								default:
									_, err := NewLPPAPDUUnsuccessfulOutcome(*value.UnsuccessfulOutcome)
									requireEnvelopeBuildError(t, err)
								}
								for _, fresh := range []bool{false, true} {
									t.Run(map[bool]string{false: "replay", true: "fresh"}[fresh], func(t *q8.T) {
										var options []q15.EncodeOption
										if fresh {
											options = append(options, q15.WithoutReplay())
										}
										_, err := value.MarshalAPER(options...)
										requireEnvelopeEncodeError(t, err)
										_, err = marshalEnvelope(&value, options...)
										requireEnvelopeEncodeError(t, err)
										bb := q15.NewBitBuffer()
										requireEnvelopeEncodeError(t, encodeEnvelope(&value, bb, fresh))
										if bb.BitPos() != 0 {
											t.Errorf("refusal emitted %d bits", bb.BitPos())
										}
										codec := LPPAPDUCodec()
										owned, _, err := codec.DecodeAPER(valueCase.wire)
										if err != nil {
											t.Fatal(err)
										}
										*envelopeCode(&owned.Value) = wrong
										_, err = codec.EncodeAPER(owned, options...)
										requireEnvelopeEncodeError(t, err)
										_, err = codec.EncodeAPER(owned.WithoutReplay())
										requireEnvelopeEncodeError(t, err)
									})
								}
							}
							*envelopeCode(&value) = original
							replay = sliceByteEnvelopeMust(value.MarshalAPER())
							if !q23.Equal(replay, valueCase.wire) {
								t.Fatal("refusal damaged received replay")
							}
						})
					}
				})
			}
		})
	}
}
func TestPrivateIEIDMustMatchOpaqueValue(t *q8.T) {
	id := privateIEIDEnvelopeMust(NewPrivateIEIDLocal(1))
	field := privateMessageIEsValuePrivateIEFieldEnvelopeMust(PrivateMessageIEs().NewOpaque(id, CriticalityIgnore, []byte{0x80}))
	valid := PrivateMessage{PrivateIEs: PrivateMessageIEsValuePrivateIEContainer{field}}
	wire := sliceByteEnvelopeMust(valid.MarshalAPER())
	for _, origin := range []string{"built", "decoded", "literal"} {
		t.Run(origin, func(t *q8.T) {
			body := valid
			if origin == "decoded" {
				if _, err := body.UnmarshalAPER(wire); err != nil {
					t.Fatal(err)
				}
			}
			fields := append(PrivateMessageIEsValuePrivateIEContainer(nil), body.PrivateIEs...)
			if origin == "literal" {
				fields[0] = PrivateMessageIEsValuePrivateIEField{Id: id, Criticality: CriticalityIgnore, Value: field.Value}
			}
			fields[0].Id = privateIEIDEnvelopeMust(NewPrivateIEIDLocal(2))
			body.PrivateIEs = fields
			report, err := ValidatePrivateMessage(&body)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range report.Issues {
				if issue.Code == ValueIDMismatch && issue.Severity == ValidationSeverityError && issue.PrivateID != nil && q12.HasSuffix(string(issue.Location.Path), ".id") {
					found = true
				}
			}
			if !found {
				t.Errorf("missing private selector issue: %+v", report)
			}
			var build *BuildError
			if _, err := NewPrivateMessage(fields); !q14.As(err, &build) {
				t.Errorf("private builder lost structural refusal: %v", err)
			}
			if _, err := PrivateMessageProcedure().Initiating().Build(body, 7); err == nil {
				t.Error("procedure builder accepted retagged private value")
			}
			for _, fresh := range []bool{false, true} {
				var options []q15.EncodeOption
				if fresh {
					options = append(options, q15.WithoutReplay())
				}
				_, err = body.MarshalAPER(options...)
				var located *q13.DecodePathError
				if !q14.Is(err, q15.ErrInvalidValue) || !q14.As(err, &located) || !q12.Contains(located.Path, "Id") {
					t.Errorf("private encoder accepted mismatch: %v", err)
				}
				bb := q15.NewBitBuffer()
				err = bridge3.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&fields[0], bb, fresh)
				if !q14.Is(err, q15.ErrInvalidValue) || bb.BitPos() != 0 {
					t.Errorf("private refusal err=%v bits=%d", err, bb.BitPos())
				}
			}
		})
	}
	// A pointer edit to the original identifier must not alter the value's binding.
	*id.Local = 3
	body := PrivateMessage{PrivateIEs: PrivateMessageIEsValuePrivateIEContainer{field}}
	if _, err := body.MarshalAPER(); !q14.Is(err, q15.ErrInvalidValue) {
		t.Errorf("aliased private ID changed its binding: %v", err)
	}
}
func TestPrivateSelectorComparisonUsesSemanticID(t *q8.T) {
	id := privateIEIDEnvelopeMust(NewPrivateIEIDGlobal(objectIdentifierEnvelopeMust(q13.ParseObjectIdentifier("1.2.840.113549"))))
	field := privateMessageIEsValuePrivateIEFieldEnvelopeMust(PrivateMessageIEs().NewOpaque(id, CriticalityIgnore, []byte{0x80}))
	body := PrivateMessage{PrivateIEs: PrivateMessageIEsValuePrivateIEContainer{field}}
	wire := sliceByteEnvelopeMust(body.MarshalAPER())
	var decoded PrivateMessage
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	// Replacing the ID by an independently constructed equal ID is allowed.
	decoded.PrivateIEs[0].Id = privateIEIDEnvelopeMust(NewPrivateIEIDGlobal(objectIdentifierEnvelopeMust(q13.ParseObjectIdentifier("1.2.840.113549"))))
	if replay := sliceByteEnvelopeMust(decoded.MarshalAPER()); !q23.Equal(replay, wire) {
		t.Fatal("equal semantic private ID changed encoding")
	}
	*decoded.PrivateIEs[0].Id.Global = objectIdentifierEnvelopeMust(q13.ParseObjectIdentifier("1.2.840.113550"))
	if _, err := decoded.MarshalAPER(); !q14.Is(err, q15.ErrInvalidValue) {
		t.Errorf("private global selector edit was accepted: %v", err)
	}
}
