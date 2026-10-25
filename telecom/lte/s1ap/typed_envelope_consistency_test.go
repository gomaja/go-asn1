// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

func requireEnvelopeMismatch(t *testing.T, pdu *s52.S1APPDU) {
	t.Helper()
	report, err := s52.ValidateMessage(pdu)
	if err != nil {
		t.Errorf("validation returned an error instead of a selector issue: %v", err)
		return
	}
	for _, issue := range report.Issues {
		if issue.Code == s00.ValueIDMismatch && issue.Severity == s00.ValidationSeverityError && !issue.HasIEID && strings.HasSuffix(string(issue.Location.Path), ".procedureCode") && issue.Rule.Document == "3GPP TS 36.413" && issue.Rule.Clause == "§10" && len(issue.RelatedRules) != 0 {
			return
		}
	}
	t.Errorf("missing envelope selector issue: %+v", report)
}
func requireEnvelopeEncodeError(t *testing.T, err error) {
	t.Helper()
	var located *runtime.DecodePathError
	if !errors.Is(err, aper.ErrInvalidValue) || !errors.As(err, &located) || !strings.Contains(located.Path, "ProcedureCode") {
		t.Errorf("missing located invalid-value refusal: %v", err)
	}
}
func requireEnvelopeBuildError(t *testing.T, err error) {
	t.Helper()
	var build *s21.BuildError
	if !errors.As(err, &build) {
		t.Errorf("builder accepted mismatched envelope or lost structural error: %v", err)
		return
	}
	if len(build.Issues) != 1 || build.Issues[0].Code != s00.ValueIDMismatch || !strings.HasSuffix(string(build.Issues[0].Location.Path), ".procedureCode") {
		t.Errorf("wrong builder issue: %+v", build.Issues)
	}
}
func envelopeCode(p *s52.S1APPDU) *s00.ProcedureCode {
	switch p.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		return &p.InitiatingMessage.ProcedureCode
	case s00.S1APPDUChoiceSuccessfulOutcome:
		return &p.SuccessfulOutcome.ProcedureCode
	default:
		return &p.UnsuccessfulOutcome.ProcedureCode
	}
}
func encodeEnvelope(p *s52.S1APPDU, bb *aper.BitBuffer, fresh bool) error {
	switch p.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		return s51.BridgeInitiatingMessageMethodMarshalAPERTo(p.InitiatingMessage, bb, fresh)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		return s50.BridgeSuccessfulOutcomeMethodMarshalAPERTo(p.SuccessfulOutcome, bb, fresh)
	default:
		return s36.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(p.UnsuccessfulOutcome, bb, fresh)
	}
}
func marshalEnvelope(p *s52.S1APPDU, options ...aper.EncodeOption) ([]byte, error) {
	switch p.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		return p.InitiatingMessage.MarshalAPER(options...)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		return p.SuccessfulOutcome.MarshalAPER(options...)
	default:
		return p.UnsuccessfulOutcome.MarshalAPER(options...)
	}
}

// TS 36.413 V19.2.0 §§9.3.2,9.3.7 bind every outcome's value to @procedureCode.
func TestEnvelopeProcedureCodeMustMatchValue(t *testing.T) {

	response := resetAcknowledgeEnvelopeMust(s50.NewResetAcknowledge(nil))
	cause := causeEnvelopeMust(s25.NewCauseProtocol(s00.CauseProtocolSemanticError))
	failure := s1SetupFailureEnvelopeMust(s49.NewS1SetupFailure(s23.S1SetupFailureIEContainer{s1SetupFailureIEFieldEnvelopeMust(s23.S1SetupFailureIEs().Cause().New(cause))}))
	initiating := initiatingMessageEnvelopeMust(s51.ErrorIndicationProcedure().Initiating().Build(errorIndicationEnvelopeMust(s49.NewErrorIndication(nil))))
	successful := successfulOutcomeEnvelopeMust(s52.ResetProcedure().Successful().Build(response))
	unsuccessful := unsuccessfulOutcomeEnvelopeMust(s52.S1SetupProcedure().Unsuccessful().Build(failure))
	cases := []struct {
		name string
		pdu  s52.S1APPDU
	}{
		{"initiating", s52.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &initiating}},
		{"successful", s52.S1APPDU{Choice: s00.S1APPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &successful}},
		{"unsuccessful", s52.S1APPDU{Choice: s00.S1APPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &unsuccessful}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			knownWire := sliceByteEnvelopeMust(tc.pdu.MarshalAPER())
			opaque := tc.pdu
			switch opaque.Choice {
			case s00.S1APPDUChoiceInitiatingMessage:
				v := initiatingMessageEnvelopeMust(s52.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0x81}))
				opaque.InitiatingMessage = &v
			case s00.S1APPDUChoiceSuccessfulOutcome:
				v := successfulOutcomeEnvelopeMust(s50.NewOpaqueSuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0x81}))
				opaque.SuccessfulOutcome = &v
			default:
				v := unsuccessfulOutcomeEnvelopeMust(s36.NewOpaqueUnsuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0x81}))
				opaque.UnsuccessfulOutcome = &v
			}
			for _, valueCase := range []struct {
				name string
				pdu  s52.S1APPDU
				wire []byte
			}{{"typed", tc.pdu, knownWire}, {"opaque", opaque, sliceByteEnvelopeMust(opaque.MarshalAPER())}} {
				t.Run(valueCase.name, func(t *testing.T) {
					for _, origin := range []string{"built", "decoded", "literal"} {
						t.Run(origin, func(t *testing.T) {
							value := valueCase.pdu
							if origin == "decoded" {
								value = s52.S1APPDU{}
								if _, err := value.UnmarshalAPER(valueCase.wire); err != nil {
									t.Fatal(err)
								}
							}
							// A literal can copy a closed value while independently choosing its outer code.
							switch value.Choice {
							case s00.S1APPDUChoiceInitiatingMessage:
								v := *value.InitiatingMessage
								value.InitiatingMessage = &s51.InitiatingMessage{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, Value: v.Value}
							case s00.S1APPDUChoiceSuccessfulOutcome:
								v := *value.SuccessfulOutcome
								value.SuccessfulOutcome = &s50.SuccessfulOutcome{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, Value: v.Value}
							default:
								v := *value.UnsuccessfulOutcome
								value.UnsuccessfulOutcome = &s36.UnsuccessfulOutcome{ProcedureCode: v.ProcedureCode, Criticality: v.Criticality, Value: v.Value}
							}
							if origin == "decoded" {
								if _, err := value.UnmarshalAPER(valueCase.wire); err != nil {
									t.Fatal(err)
								}
							}
							replay := sliceByteEnvelopeMust(value.MarshalAPER())
							if !bytes.Equal(replay, valueCase.wire) {
								t.Fatal("matching selector changed replay")
							}
							original := *envelopeCode(&value)
							for _, wrong := range []s00.ProcedureCode{1, 249} {
								*envelopeCode(&value) = wrong
								requireEnvelopeMismatch(t, &value)
								switch value.Choice {
								case s00.S1APPDUChoiceInitiatingMessage:
									_, err := s52.NewS1APPDUInitiatingMessage(*value.InitiatingMessage)
									requireEnvelopeBuildError(t, err)
								case s00.S1APPDUChoiceSuccessfulOutcome:
									_, err := s52.NewS1APPDUSuccessfulOutcome(*value.SuccessfulOutcome)
									requireEnvelopeBuildError(t, err)
								default:
									_, err := s52.NewS1APPDUUnsuccessfulOutcome(*value.UnsuccessfulOutcome)
									requireEnvelopeBuildError(t, err)
								}
								for _, fresh := range []bool{false, true} {
									t.Run(map[bool]string{false: "replay", true: "fresh"}[fresh], func(t *testing.T) {
										var options []aper.EncodeOption
										if fresh {
											options = append(options, aper.WithoutReplay())
										}
										_, err := value.MarshalAPER(options...)
										requireEnvelopeEncodeError(t, err)
										_, err = marshalEnvelope(&value, options...)
										requireEnvelopeEncodeError(t, err)
										bb := aper.NewBitBuffer()
										requireEnvelopeEncodeError(t, encodeEnvelope(&value, bb, fresh))
										if bb.BitPos() != 0 {
											t.Errorf("refusal emitted %d bits", bb.BitPos())
										}
										codec := s52.S1APPDUCodec()
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
							if !bytes.Equal(replay, valueCase.wire) {
								t.Fatal("refusal damaged received replay")
							}
						})
					}
				})
			}
		})
	}
}
func TestPrivateIEIDMustMatchOpaqueValue(t *testing.T) {
	id := privateIEIDEnvelopeMust(s26.NewPrivateIEIDLocal(1))
	field := privateMessageIEsValuePrivateIEFieldEnvelopeMust(s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	valid := s26.PrivateMessage{PrivateIEs: s25.PrivateMessageIEsValuePrivateIEContainer{field}}
	wire := sliceByteEnvelopeMust(valid.MarshalAPER())
	for _, origin := range []string{"built", "decoded", "literal"} {
		t.Run(origin, func(t *testing.T) {
			body := valid
			if origin == "decoded" {
				if _, err := body.UnmarshalAPER(wire); err != nil {
					t.Fatal(err)
				}
			}
			fields := append(s25.PrivateMessageIEsValuePrivateIEContainer(nil), body.PrivateIEs...)
			if origin == "literal" {
				fields[0] = s25.PrivateMessageIEsValuePrivateIEField{Id: id, Criticality: s00.CriticalityIgnore, Value: field.Value}
			}
			fields[0].Id = privateIEIDEnvelopeMust(s26.NewPrivateIEIDLocal(2))
			body.PrivateIEs = fields
			report, err := s47.ValidatePrivateMessage(&body)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, issue := range report.Issues {
				if issue.Code == s00.ValueIDMismatch && issue.Severity == s00.ValidationSeverityError && issue.PrivateID != nil && strings.HasSuffix(string(issue.Location.Path), ".id") {
					found = true
				}
			}
			if !found {
				t.Errorf("missing private selector issue: %+v", report)
			}
			var build *s21.BuildError
			if _, err := s47.NewPrivateMessage(fields); !errors.As(err, &build) {
				t.Errorf("private builder lost structural refusal: %v", err)
			}
			if _, err := s52.PrivateMessageProcedure().Initiating().Build(body); err == nil {
				t.Error("procedure builder accepted retagged private value")
			}
			for _, fresh := range []bool{false, true} {
				var options []aper.EncodeOption
				if fresh {
					options = append(options, aper.WithoutReplay())
				}
				_, err = body.MarshalAPER(options...)
				var located *runtime.DecodePathError
				if !errors.Is(err, aper.ErrInvalidValue) || !errors.As(err, &located) || !strings.Contains(located.Path, "Id") {
					t.Errorf("private encoder accepted mismatch: %v", err)
				}
				bb := aper.NewBitBuffer()
				err = s25.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&fields[0], bb, fresh)
				if !errors.Is(err, aper.ErrInvalidValue) || bb.BitPos() != 0 {
					t.Errorf("private refusal err=%v bits=%d", err, bb.BitPos())
				}
			}
		})
	}
	// A pointer edit to the original identifier must not alter the value's binding.
	*id.Local = 3
	body := s26.PrivateMessage{PrivateIEs: s25.PrivateMessageIEsValuePrivateIEContainer{field}}
	if _, err := body.MarshalAPER(); !errors.Is(err, aper.ErrInvalidValue) {
		t.Errorf("aliased private ID changed its binding: %v", err)
	}
}
func TestPrivateSelectorComparisonUsesSemanticID(t *testing.T) {
	id := privateIEIDEnvelopeMust(s26.NewPrivateIEIDGlobal(objectIdentifierEnvelopeMust(runtime.ParseObjectIdentifier("1.2.840.113549"))))
	field := privateMessageIEsValuePrivateIEFieldEnvelopeMust(s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	body := s26.PrivateMessage{PrivateIEs: s25.PrivateMessageIEsValuePrivateIEContainer{field}}
	wire := sliceByteEnvelopeMust(body.MarshalAPER())
	var decoded s26.PrivateMessage
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	// Replacing the ID by an independently constructed equal ID is allowed.
	decoded.PrivateIEs[0].Id = privateIEIDEnvelopeMust(s26.NewPrivateIEIDGlobal(objectIdentifierEnvelopeMust(runtime.ParseObjectIdentifier("1.2.840.113549"))))
	if replay := sliceByteEnvelopeMust(decoded.MarshalAPER()); !bytes.Equal(replay, wire) {
		t.Fatal("equal semantic private ID changed encoding")
	}
	*decoded.PrivateIEs[0].Id.Global = objectIdentifierEnvelopeMust(runtime.ParseObjectIdentifier("1.2.840.113550"))
	if _, err := decoded.MarshalAPER(); !errors.Is(err, aper.ErrInvalidValue) {
		t.Errorf("private global selector edit was accepted: %v", err)
	}
}
