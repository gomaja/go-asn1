// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	sync "sync"
	testing "testing"
)

// TS 36.413 V19.2.0 §§10.1–10.3:
// unknown identifiers are preserved; a known malformed value is a fatal error.
func TestReceiverModeReportsAndAtomicReuse(t *testing.T) {
	unknown, err := s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	known, err := s28.ErrorIndicationIEs().CriticalityDiagnostics().New(s22.CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s49.NewErrorIndication(s28.ErrorIndicationIEContainer{unknown, known})
	if err != nil {
		t.Fatal(err)
	}
	message, err := s51.ErrorIndicationProcedure().Initiating().Build(body)
	if err != nil {
		t.Fatal(err)
	}
	value, err := s52.NewS1APPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := value.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var reused s52.S1APPDU
		for range 2 {
			report, err := reused.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 1 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			observation := report.Observations[0]
			if observation.Kind != aper.UnknownIE || observation.Location.Path == "" || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 || observation.Rule.Document != "3GPP TS 36.413" {
				t.Fatalf("observation=%+v", observation)
			}
			replay, err := reused.MarshalAPER()
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay=%x err=%v", replay, err)
			}
			malformed := bytes.Clone(wire)
			malformed[len(malformed)-1] |= 1
			report, err = reused.UnmarshalAPER(malformed, options...)
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || len(report.Observations) != 1 || len(report.Deviations) != 1 {
				t.Fatalf("failed report=%+v err=%v", report, err)
			}
			if report.Deviations[0].Rule != located.Rule || report.Deviations[0].Location.Path != located.Location.Path || !strings.Contains(string(located.Location.Path), "ProtocolIEs[1].Value") {
				t.Fatalf("duplicate or wrong occurrence: %+v / %+v", report, located)
			}
			if reused.Choice != 0 || reused.ReceivedForm().Present() {
				t.Fatalf("failed value retained: %+v", reused)
			}
		}
		codecValue, report, err := s52.S1APPDUCodec().DecodeAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 {
			t.Fatalf("codec report=%+v err=%v", report, err)
		}
		replay, err := s52.S1APPDUCodec().EncodeAPER(codecValue)
		if err != nil || !bytes.Equal(wire, replay) {
			t.Fatalf("codec replay=%x err=%v", replay, err)
		}
	}
}
func TestValidationHandlingProvenance(t *testing.T) {
	field, err := s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	body := s28.ErrorIndication{ProtocolIEs: s28.ErrorIndicationIEContainer{field}}
	report, err := s49.ValidateErrorIndication(&body)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	issue := report.Issues[0]
	if issue.Code != s00.NotAllowed || issue.Severity != s00.ValidationSeverityUnrecognized || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.1" || issue.RelatedRules[1].Clause != "§10.3.4.2" {
		t.Fatalf("handling: %+v", issue)
	}
	message, err := s50.NewOpaqueSuccessfulOutcome(s00.IdErrorIndication, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	pdu := s52.S1APPDU{Choice: s00.S1APPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &message}
	report, err = s52.ValidateMessage(&pdu)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("outcome report=%+v err=%v", report, err)
	}
	issue = report.Issues[0]
	if issue.Code != s00.UnavailableOutcome || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.4.1" || issue.RelatedRules[1].Clause != "§10.3.4.1A" {
		t.Fatalf("outcome handling: %+v", issue)
	}
}
func TestReceiverReportsOnlyUnknownBoundaries(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		opaque, err := s52.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		unknown, err := s52.NewS1APPDUInitiatingMessage(opaque)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := unknown.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var pdu s52.S1APPDU
		report, err := pdu.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Kind != aper.UnknownProcedure {
			t.Fatalf("procedure report=%+v err=%v", report, err)
		}
		choice, err := s52.NewS1APPDUUnknownExtension(7, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err = choice.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		report, err = pdu.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Kind != aper.UnknownExtension {
			t.Fatalf("choice report=%+v err=%v", report, err)
		}
		known := s22.CriticalityDiagnostics{}
		if err := known.SetExtension(0, []byte{0}); err != nil {
			t.Fatal(err)
		}
		wire, err = known.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded s22.CriticalityDiagnostics
		report, err = decoded.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Rule.Clause != "§9.3.4" {
			t.Fatalf("sequence source rule=%+v err=%v", report, err)
		}

	}
}
func receiverUnknownWire(t *testing.T, count int) []byte {
	t.Helper()
	field, err := s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	fields := make(s28.ErrorIndicationIEContainer, count)
	for i := range fields {
		fields[i] = field
		fields[i], err = s28.ErrorIndicationIEs().NewOpaque(s00.ProtocolIEID(60000+i), s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
	}
	body := s28.ErrorIndication{ProtocolIEs: fields}
	message := s51.InitiatingMessage{ProcedureCode: s00.IdErrorIndication, Criticality: s00.CriticalityIgnore, Value: func() s51.InitiatingValue {
		sealed := s51.InitiatingValue{}
		*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.IdErrorIndication
		*s51.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := s52.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func TestReceiverDefaultReportCeilingAndLinearGrowth(t *testing.T) {
	var previous float64
	for _, size := range []int{128, 256, 512} {
		wire := receiverUnknownWire(t, size)
		allocations := testing.AllocsPerRun(3, func() {
			var value s52.S1APPDU
			report, err := value.UnmarshalAPER(wire, aper.WithReceiverMode())
			if err != nil || len(report.Observations) != size {
				panic("unknown observations lost")
			}
		})
		if previous != 0 && allocations > previous*3 {
			t.Fatalf("reports grew superlinearly: size=%d allocations=%v previous=%v", size, allocations, previous)
		}
		previous = allocations
	}
	valid := receiverUnknownWire(t, 1)
	for _, size := range []int{1023, 1024, 1025} {
		wire := receiverUnknownWire(t, size)
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var reused s52.S1APPDU
			if _, err := reused.UnmarshalAPER(valid, options...); err != nil {
				t.Fatal(err)
			}
			for _, value := range []*s52.S1APPDU{new(s52.S1APPDU), &reused} {
				report, err := value.UnmarshalAPER(wire, options...)
				if size <= 1024 {
					if err != nil || len(report.Observations) != size {
						t.Fatalf("size=%d report=%+v err=%v", size, report, err)
					}
				} else {
					var located *aper.DecodeError
					if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || !located.Location.HasWireLocation || located.Location.Path == "" || len(report.Observations) != 1024 || value.Choice != 0 || value.ReceivedForm().Present() {
						t.Fatalf("report overflow size=%d observations=%d value=%+v err=%v location=%+v", size, len(report.Observations), value, err, located)
					}
				}
			}
		}
	}
}
func TestGeneratedReceiverOptionsSharedAcrossCalls(t *testing.T) {
	wire := receiverUnknownWire(t, 8)
	options := []aper.DecodeOption{aper.WithReceiverMode(), aper.WithLimits(aper.DefaultLimits())}
	codec := s52.S1APPDUCodec()
	encodeOptions := []aper.EncodeOption{aper.WithEncodeLimits(aper.DefaultLimits())}
	validationOptions := []aper.ValidationOption{aper.WithValidationLimits(aper.DefaultLimits())}
	buildOptions := []aper.BuildOption{aper.WithBuildLimits(aper.DefaultLimits())}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 20 {
				value, report, err := codec.DecodeAPER(wire, options...)
				if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 8 {
					t.Errorf("shared options report=%+v err=%v", report, err)
					return
				}
				replay, err := codec.EncodeAPER(value, encodeOptions...)
				if err != nil || !bytes.Equal(replay, wire) {
					t.Errorf("shared options replay=%x err=%v", replay, err)
					return
				}
				if _, err := s52.ValidateMessage(&value.Value, validationOptions...); err != nil {
					t.Error(err)
					return
				}
				if _, err := s52.NewS1APPDUInitiatingMessage(*value.Value.InitiatingMessage, buildOptions...); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
}

// X.691 (02/2021) §14.3: an unrecognized extension index is legal.
func TestUnknownEnumerationObservation(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		value, report, err := s23.TimeToWaitCodec().DecodeAPER([]byte{0x80}, options...)
		if err != nil || value.Value != s00.TimeToWait(6) || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("unknown enum value=%v report=%+v err=%v", value.Value, report, err)
		}
		observation := report.Observations[0]
		if observation.Kind != aper.UnknownExtension || observation.Rule.Clause != "§14.3" || !observation.Location.HasWireLocation || observation.Location.Path == "" {
			t.Fatalf("observation=%+v", observation)
		}
		replay, err := s23.TimeToWaitCodec().EncodeAPER(value)
		if err != nil || !bytes.Equal(replay, []byte{0x80}) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
		// CauseRadioNetwork has the known NR addition.
		_, report, err = s02.CauseRadioNetworkCodec().DecodeAPER([]byte{0x80}, options...)
		if err != nil || len(report.Observations) != 0 {
			t.Fatalf("known enum report=%+v err=%v", report, err)
		}
	}
}
func TestPublicOperationLimitBoundaries(t *testing.T) {
	wire := receiverUnknownWire(t, 8)
	setters := []struct {
		name                            string
		set                             func(uint64) aper.Limits
		decode, encode, build, validate bool
	}{
		{"input", func(n uint64) aper.Limits { return aper.Limits{MaxInputBytes: n} }, true, false, false, false},
		{"output", func(n uint64) aper.Limits { return aper.Limits{MaxOutputBytes: n} }, false, true, true, false},
		{"open", func(n uint64) aper.Limits { return aper.Limits{MaxOpenTypeBytes: n} }, true, true, true, true},
		{"depth", func(n uint64) aper.Limits { return aper.Limits{MaxDepth: n} }, true, true, true, true},
		{"elements", func(n uint64) aper.Limits { return aper.Limits{MaxElements: n} }, true, true, true, true},
		{"fragments", func(n uint64) aper.Limits { return aper.Limits{MaxFragments: n} }, true, true, true, true},
		{"work", func(n uint64) aper.Limits { return aper.Limits{MaxWork: n} }, true, true, true, true},
		{"allocation", func(n uint64) aper.Limits { return aper.Limits{MaxAllocatedBytes: n} }, true, true, true, true},
		{"reports", func(n uint64) aper.Limits { return aper.Limits{MaxReports: n} }, true, false, true, true},
	}
	var original s52.S1APPDU
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	for _, setter := range setters {
		ops := []struct {
			name    string
			enabled bool
			run     func(aper.Limits) error
		}{
			{"decode", setter.decode, func(limits aper.Limits) error {
				var v s52.S1APPDU
				_, err := v.UnmarshalAPER(wire, aper.WithLimits(limits))
				return err
			}},
			{"encode", setter.encode, func(limits aper.Limits) error {
				_, err := original.MarshalAPER(aper.WithEncodeLimits(limits))
				return err
			}},
			{"build", setter.build, func(limits aper.Limits) error {
				_, err := s52.NewS1APPDUInitiatingMessage(*original.InitiatingMessage, aper.WithBuildLimits(limits))
				return err
			}},
			{"validate", setter.validate, func(limits aper.Limits) error {
				_, err := s52.ValidateMessage(&original, aper.WithValidationLimits(limits))
				return err
			}},
		}
		for _, op := range ops {
			if !op.enabled {
				continue
			}
			t.Run(op.name+"/"+setter.name, func(t *testing.T) {
				// Locate a transition, then test both adjacent limits independently.
				var low uint64 = 1
				high := uint64(aper.DefaultLimits().MaxAllocatedBytes)
				for low < high {
					middle := low + (high-low)/2
					err := op.run(setter.set(middle))
					if errors.Is(err, aper.ErrLimit) {
						low = middle + 1
					} else if err != nil {
						t.Fatal(err)
					} else {
						high = middle
					}
				}
				required := low
				if required <= 1 {
					t.Fatalf("%s ceiling is not enforced", setter.name)
				}
				for _, limit := range []uint64{required - 1, required, required + 1} {
					err := op.run(setter.set(limit))
					if (limit < required) != errors.Is(err, aper.ErrLimit) {
						t.Fatalf("limit=%d required=%d err=%v", limit, required, err)
					}
				}
				t.Logf("minimum %s %s=%d", op.name, setter.name, required)
				if op.name == "decode" {
					for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
						var reused s52.S1APPDU
						for _, limit := range []uint64{required, required - 1, required + 1} {
							opts := append([]aper.DecodeOption{}, options...)
							opts = append(opts, aper.WithLimits(setter.set(limit)))
							report, err := reused.UnmarshalAPER(wire, opts...)
							if (limit < required) != errors.Is(err, aper.ErrLimit) {
								t.Fatalf("reused limit=%d report=%+v err=%v", limit, report, err)
							}
							if err != nil && reused.Choice != 0 {
								t.Fatal("limit retained old receiver")
							}
						}
					}
				}
			})
		}
	}
}
func TestAllOperationBudgetsGrowLinearly(t *testing.T) {
	var previous [4]aper.DecodeUsage
	for _, size := range []int{64, 128, 256} {
		wire := receiverUnknownWire(t, size)
		var value s52.S1APPDU
		state := aper.ApplyDecodeOptions()
		if err := s52.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&value, wire, state); err != nil {
			t.Fatal(err)
		}
		var usages [4]aper.DecodeUsage
		usages[0] = state.Usage()
		encode, err := aper.EncodeBudget()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s52.BridgeS1APPDUMethodMarshalAPERBudget(&value, encode, false); err != nil {
			t.Fatal(err)
		}
		usages[1] = aper.NewBudgetBuffer(encode).Usage()
		validate, err := aper.ValidationBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err := s52.BridgeValidateMessageBudget(&value, validate)
		if err != nil || *s21.BridgeValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s52.BridgeS1APPDUMethodMarshalAPERBudget(&value, validate, false); err != nil {
			t.Fatal(err)
		}
		usages[2] = aper.NewBudgetBuffer(validate).Usage()
		build, err := aper.BuildBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err = s52.BridgeValidateMessageBudget(&value, build)
		if err != nil || *s21.BridgeValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s52.BridgeS1APPDUMethodMarshalAPERBudget(&value, build, false); err != nil {
			t.Fatal(err)
		}
		usages[3] = aper.NewBudgetBuffer(build).Usage()
		for i, usage := range usages {
			if previous[i].Work != 0 && (usage.Work > previous[i].Work*3 || usage.AllocatedBytes > previous[i].AllocatedBytes*3) {
				t.Fatalf("size=%d operation=%d usage=%+v previous=%+v", size, i, usage, previous[i])
			}
			previous[i] = usage
		}
		// A failed decode keeps work and allocations charged to the same state.
		failed := aper.ApplyDecodeOptions(aper.WithLimits(aper.Limits{MaxReports: uint64(size - 1)}))
		var rejected s52.S1APPDU
		err = s52.BridgeS1APPDUMethodUnmarshalAPERWithOptions(&rejected, wire, failed)
		_, err = aper.FinishDecode(failed, err)
		if !errors.Is(err, aper.ErrLimit) || failed.Usage().Work > usages[0].Work || failed.Usage().AllocatedBytes > usages[0].AllocatedBytes {
			t.Fatalf("failed-path budget=%+v success=%+v err=%v", failed.Usage(), usages[0], err)
		}
	}
}
func TestZeroUnionMatchesNoRow(t *testing.T) {
	budget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	if s48.BridgeHandoverRequestIEValueMethodMatchesID((s48.HandoverRequestIEValue{}), 0, budget) {
		t.Fatal("a zero union matched id zero without an arm")
	}
}
func TestEnvelopeFindingsRespectTheSameReportCeiling(t *testing.T) {
	wire := receiverUnknownWire(t, 2)
	var value s52.S1APPDU
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value.InitiatingMessage.Criticality = s00.CriticalityReject
	report, err := s52.ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 2}))
	var located *aper.DecodeError
	if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || located.Location.Path == "" || len(report.Issues) > 2 || located.Location.HasWireLocation {
		t.Fatalf("report=%+v err=%v location=%+v", report, err, located)
	}
	if _, err := s52.ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 3})); err != nil {
		t.Fatal(err)
	}
}
func TestPDUUnusedRootChoiceIndex(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s52.S1APPDU
		report, err := value.UnmarshalAPER([]byte{0x60}, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§11.5.7.1" || !strings.Contains(string(located.Location.Path), "S1APPDU") || len(report.Deviations) != 1 {
			t.Fatalf("unused choice: report=%+v err=%v location=%+v", report, err, located)
		}
	}
}
func TestDescriptorBuildFailuresHaveOwnedIdentity(t *testing.T) {
	body, err := s49.NewErrorIndication(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func() error{
		func() error { _, err := (s51.ErrorIndicationInitiatingBinding{}).Build(body); return err },
		func() error { _, err := (ErrorIndicationSuccessfulBinding{}).Build(body); return err },
		func() error { _, err := (ErrorIndicationUnsuccessfulBinding{}).Build(body); return err },
	} {
		var located *aper.DecodeError
		err := run()
		if !errors.Is(err, aper.ErrInvalidValue) || !errors.As(err, &located) || located.Location.Path == "" || located.Location.HasWireLocation {
			t.Fatalf("build error=%v location=%+v", err, located)
		}
	}
}
func TestPayloadBoundaryErrorsAreLocated(t *testing.T) {
	check := func(err, errorKind error) {
		t.Helper()
		var located *aper.DecodeError
		if !errors.Is(err, errorKind) || !errors.As(err, &located) || located.Location.Path == "" || located.Location.HasWireLocation {
			t.Fatalf("payload err=%v location=%+v", err, located)
		}
	}
	_, err := (s51.NewPayloadCodec[int]{}).Call(nil, nil)
	check(err, aper.ErrInvalidValue)
	_, _, err = (s51.DecodePayload[int]{}).Call([]byte{1}, s51.PayloadCodec[int]{}, s00.PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	_, err = (s51.EncodePayload[int]{}).Call(1, s51.PayloadCodec[int]{}, s00.PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	codec, err := (s51.NewPayloadCodec[int]{}).Call(func(data []byte, _ s00.PayloadLimits) (int, s00.PayloadReport, error) {
		return len(data), s00.PayloadReport{Deviations: []s00.PayloadDeviation{{Path: "a"}, {Path: "b"}}}, nil
	}, func(int, s00.PayloadLimits) ([]byte, error) { return []byte{1, 2}, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []s00.PayloadLimits{{MaxInputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}, {MaxReports: 1}} {
		_, _, err = (s51.DecodePayload[int]{}).Call([]byte{1, 2}, codec, limits)
		check(err, aper.ErrLimit)
	}
	for _, limits := range []s00.PayloadLimits{{MaxOutputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}} {
		_, err = (s51.EncodePayload[int]{}).Call(2, codec, limits)
		check(err, aper.ErrLimit)
	}
}
func TestMalformedPrimitiveReportIsLocated(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		_, report, err := s23.TimeToWaitCodec().DecodeAPER([]byte{15}, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path != "TimeToWait" || located.Rule.Clause != "§11.1.4" || len(report.Deviations) != 1 || report.Deviations[0].Location.Path != located.Location.Path || report.Deviations[0].Rule != located.Rule {
			t.Fatalf("primitive report=%+v err=%v location=%+v", report, err, located)
		}
	}
}
func TestDuplicateUnknownValidationReportLimit(t *testing.T) {
	field, err := s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	body := s28.ErrorIndication{ProtocolIEs: s28.ErrorIndicationIEContainer{field, field}}
	report, err := s49.ValidateErrorIndication(&body, aper.WithValidationLimits(aper.Limits{MaxReports: 2}))
	if !errors.Is(err, aper.ErrLimit) || len(report.Issues) > 2 {
		t.Fatalf("duplicate report overflow: %+v %v", report, err)
	}
	report, err = s49.ValidateErrorIndication(&body, aper.WithValidationLimits(aper.Limits{MaxReports: 3}))
	if err != nil || len(report.Issues) != 3 {
		t.Fatalf("duplicate reports: %+v %v", report, err)
	}
	repeated := 0
	for _, issue := range report.Issues {
		if issue.Code == s00.RepeatedIE {
			repeated++
		}
	}
	if repeated != 1 {
		t.Fatalf("repeated findings=%d", repeated)
	}
	if _, err := s49.NewErrorIndication(body.ProtocolIEs); !errors.Is(err, aper.ErrInvalidValue) {
		t.Fatalf("duplicate unknown built: %v", err)
	}
}
func TestEveryObservationNamesItsMember(t *testing.T) {
	check := func(report aper.DecodeReport, err error, want aper.Path) {
		t.Helper()
		if err != nil || len(report.Observations) != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		observation := report.Observations[0]
		if observation.Location.Path != want || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 || observation.Rule.Document == "" || observation.Rule.Clause == "" {
			t.Fatalf("observation=%+v want=%s", observation, want)
		}
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		unknown, err := s52.NewS1APPDUUnknownExtension(7, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := unknown.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var pdu s52.S1APPDU
		report, err := pdu.UnmarshalAPER(wire, options...)
		check(report, err, "UnknownExtension")
		cd := s22.CriticalityDiagnostics{}
		if err := cd.SetExtension(3, []byte{0}); err != nil {
			t.Fatal(err)
		}
		wire, err = cd.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded s22.CriticalityDiagnostics
		report, err = decoded.UnmarshalAPER(wire, options...)
		check(report, err, "Extensions[3]")
		if report.Observations[0].Location.Path != decoded.Extensions()[0].Origin().Location.Path {
			t.Fatal("sequence view and observation disagree")
		}
		opaque, err := s52.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err = opaque.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var envelope s51.InitiatingMessage
		report, err = envelope.UnmarshalAPER(wire, options...)
		check(report, err, "InitiatingMessage.Value")
		wire = receiverUnknownWire(t, 1)
		report, err = pdu.UnmarshalAPER(wire, options...)
		check(report, err, "ProtocolIEField.Value")
		_, report, err = s23.TimeToWaitCodec().DecodeAPER([]byte{0x80}, options...)
		check(report, err, "TimeToWait")
	}
}
func TestKnownChoiceAddsNoUnknownObservation(t *testing.T) {
	known, err := s25.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := known.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s15.ENBID
		report, err := value.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
			t.Fatalf("known addition report=%+v err=%v", report, err)
		}
	}
}
func TestReplayedStandaloneBodyEnforcesOpenCeiling(t *testing.T) {
	field, err := s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s49.NewErrorIndication(s28.ErrorIndicationIEContainer{field})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded s28.ErrorIndication
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	limits := aper.Limits{MaxOpenTypeBytes: 1}
	for _, options := range [][]aper.EncodeOption{{aper.WithEncodeLimits(limits)}, {aper.WithEncodeLimits(limits), aper.WithoutReplay()}} {
		if _, err := decoded.MarshalAPER(options...); !errors.Is(err, aper.ErrLimit) {
			t.Fatalf("standalone field exceeded open ceiling: %v", err)
		}
	}
	if _, err := s49.ValidateErrorIndication(&decoded, aper.WithValidationLimits(limits)); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("standalone validation exceeded open ceiling: %v", err)
	}
	if _, err := s49.NewErrorIndication(decoded.ProtocolIEs, aper.WithBuildLimits(limits)); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("standalone build exceeded open ceiling: %v", err)
	}
}
func TestKnownChoicePaddingFailureHasOneOriginalLocation(t *testing.T) {
	known, err := s25.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := known.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] |= 1
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s15.ENBID
		report, err := value.UnmarshalAPER(wire, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || len(report.Deviations) != 1 || len(report.Observations) != 0 || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Rule.Clause != "§11.1.4" || !strings.Contains(string(located.Location.Path), "ShortMacroENBID") {
			t.Fatalf("known choice report=%+v err=%v location=%+v", report, err, located)
		}
		span := located.Location.Spans[0]
		if span.End != uint64(len(wire))*8 || span.Start != span.End-6 {
			t.Fatalf("known choice span=%+v", span)
		}
	}
}
func TestKnownChoiceAdditionsDoNotConsumeReports(t *testing.T) {
	known, err := s25.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	field, err := s43.S1SetupRequestIEs().GlobalENBID().New(s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: known})
	if err != nil {
		t.Fatal(err)
	}
	body := s44.S1SetupRequest{ProtocolIEs: s43.S1SetupRequestIEContainer{field, field}}
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var value s44.S1SetupRequest
	report, err := value.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxReports: 1}))
	if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
		t.Fatalf("known choice exhausted reports: %+v %v", report, err)
	}
}
