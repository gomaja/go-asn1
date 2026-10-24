package lppa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s24"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"strings"
	"sync"
	"testing"
)

// TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §§10.1–10.3:
// unknown identifiers are preserved; a known malformed value is a fatal error.
func TestReceiverModeReportsAndAtomicReuse(t *testing.T) {
	unknown, err := ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, []byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	known, err := ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewErrorIndication(ErrorIndicationIEContainer{unknown, known})
	if err != nil {
		t.Fatal(err)
	}
	message, err := ErrorIndicationProcedure().Initiating().Build(body, 7)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewLPPAPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := value.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var reused LPPAPDU
		for range 2 {
			report, err := reused.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 1 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			observation := report.Observations[0]
			if observation.Kind != aper.UnknownIE || observation.Location.Path != "ProtocolIEField.Value" || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 || observation.Rule.Document != "3GPP TS 36.455" {
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
		codecValue, report, err := LPPAPDUCodec().DecodeAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 {
			t.Fatalf("codec report=%+v err=%v", report, err)
		}
		replay, err := LPPAPDUCodec().EncodeAPER(codecValue)
		if err != nil || !bytes.Equal(wire, replay) {
			t.Fatalf("codec replay=%x err=%v", replay, err)
		}
	}
}
func TestValidationHandlingProvenance(t *testing.T) {
	field, err := ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	report, err := ValidateErrorIndication(&body)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	issue := report.Issues[0]
	if issue.Code != NotAllowed || issue.Severity != ValidationSeverityUnrecognized || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.1" || issue.RelatedRules[1].Clause != "§10.3.4.2" {
		t.Fatalf("handling: %+v", issue)
	}
	message, err := NewOpaqueSuccessfulOutcome(0, CriticalityIgnore, 7, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &message}
	report, err = ValidateMessage(&pdu)
	if err != nil || len(report.Issues) != 1 {
		t.Fatalf("outcome report=%+v err=%v", report, err)
	}
	issue = report.Issues[0]
	if issue.Code != UnavailableOutcome || len(issue.RelatedRules) != 2 || issue.RelatedRules[0].Clause != "§10.3.4.1" || issue.RelatedRules[1].Clause != "§10.3.4.1A" {
		t.Fatalf("outcome handling: %+v", issue)
	}
}
func TestReceiverReportsOnlyUnknownBoundaries(t *testing.T) {
	for _, mode := range []struct {
		name    string
		options []aper.DecodeOption
	}{
		{"strict", nil}, {"receiver", []aper.DecodeOption{aper.WithReceiverMode()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			options := mode.options
			testChoiceExtensionClassification(t, options)
			check := func(name string, report aper.DecodeReport, err error, kind aper.ObservationKind, path aper.Path, clause string) {
				t.Helper()
				if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
					t.Fatalf("%s: report=%+v err=%v", name, report, err)
				}
				observation := report.Observations[0]
				if observation.Kind != kind || observation.Rule.Clause != clause || observation.Location.Path != path || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 {
					t.Errorf("%s: observation=%+v, want kind=%v path=%q clause=%s", name, observation, kind, path, clause)
				}
			}
			replay := func(name string, wire, got []byte, err error) {
				t.Helper()
				if err != nil || !bytes.Equal(wire, got) {
					t.Errorf("%s: replay=%x want=%x err=%v", name, got, wire, err)
				}
			}
			opaque, err := NewOpaqueInitiatingMessage(250, CriticalityIgnore, 7, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			unknown, err := NewLPPAPDUInitiatingMessage(opaque)
			if err != nil {
				t.Fatal(err)
			}
			successful, err := NewOpaqueSuccessfulOutcome(250, CriticalityIgnore, 7, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			unsuccessful, err := NewOpaqueUnsuccessfulOutcome(250, CriticalityIgnore, 7, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			for _, procedure := range []struct {
				name  string
				value LPPAPDU
				path  aper.Path
			}{
				{"initiating", unknown, "InitiatingMessage.Value"},
				{"successful", LPPAPDU{Choice: LPPAPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &successful}, "SuccessfulOutcome.Value"},
				{"unsuccessful", LPPAPDU{Choice: LPPAPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &unsuccessful}, "UnsuccessfulOutcome.Value"},
			} {
				wire, err := procedure.value.MarshalAPER()
				if err != nil {
					t.Fatal(err)
				}
				var decoded LPPAPDU
				report, err := decoded.UnmarshalAPER(wire, options...)
				check(procedure.name, report, err, aper.UnknownProcedure, procedure.path, "§9.3.3")
				got, err := decoded.MarshalAPER()
				replay(procedure.name, wire, got, err)
			}
			choice, err := NewLPPAPDUUnknownExtension(7, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := choice.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var pdu LPPAPDU
			report, err := pdu.UnmarshalAPER(wire, options...)
			check("choice", report, err, aper.UnknownExtension, "UnknownExtension", "§23.8")
			if pdu.UnknownExtension.Origin().Location.Path != "UnknownExtension" {
				t.Errorf("choice origin=%+v", pdu.UnknownExtension.Origin())
			}
			got, err := pdu.MarshalAPER()
			replay("choice", wire, got, err)

			field, err := ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
			wire, err = body.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decodedBody ErrorIndication
			report, err = decodedBody.UnmarshalAPER(wire, options...)
			check("protocol IE", report, err, aper.UnknownIE, "ProtocolIEField.Value", "§9.3.4")
			got, err = decodedBody.MarshalAPER()
			replay("protocol IE", wire, got, err)

			extension, err := ResultsPerSSBIndexItemExtIEs().NewOpaque(65532, CriticalityIgnore, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			item := ResultsPerSSBIndexItem{IEExtensions: ResultsPerSSBIndexItemExtIEsExtContainer{extension}}
			wire, err = item.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decodedItem ResultsPerSSBIndexItem
			report, err = decodedItem.UnmarshalAPER(wire, options...)
			check("extension IE", report, err, aper.UnknownIE, "ProtocolExtensionField.ExtensionValue", "§9.3.5")
			got, err = decodedItem.MarshalAPER()
			replay("extension IE", wire, got, err)

			id, err := NewPrivateIEIDLocal(1)
			if err != nil {
				t.Fatal(err)
			}
			private, err := PrivateMessageIEs().NewOpaque(id, CriticalityIgnore, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			privateBody := PrivateMessage{PrivateIEs: PrivateMessageIEsValuePrivateIEContainer{private}}
			wire, err = privateBody.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decodedPrivate PrivateMessage
			report, err = decodedPrivate.UnmarshalAPER(wire, options...)
			check("private IE", report, err, aper.UnknownIE, "PrivateIEField.Value", "§9.3.4")
			got, err = decodedPrivate.MarshalAPER()
			replay("private IE", wire, got, err)

			value := int64(1)
			known := NPRSSubframePartB{SIB1NBSubframeTDD: &value}
			wire, err = known.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decoded NPRSSubframePartB
			report, err = decoded.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 {
				t.Fatalf("known addition reported opaque: %+v err=%v", report, err)
			}
			if err := known.SetExtension(1, []byte{0}); err != nil {
				t.Fatal(err)
			}
			unknownWire, err := known.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			unknownReport, err := decoded.UnmarshalAPER(unknownWire, options...)
			check("sequence", unknownReport, err, aper.UnknownExtension, "Extensions[1]", "§9.3.5")
			if extensions := decoded.Extensions(); len(extensions) != 1 || extensions[0].Origin().Location.Path != "Extensions[1]" {
				t.Errorf("sequence origins=%+v", extensions)
			}
			got, err = decoded.MarshalAPER()
			replay("sequence", unknownWire, got, err)
			// Sparse additions use their bitmap indexes, not their position in the view.
			var sparse ErrorIndication
			if err := sparse.SetExtension(0, []byte{0}); err != nil {
				t.Fatal(err)
			}
			if err := sparse.SetExtension(3, []byte{1}); err != nil {
				t.Fatal(err)
			}
			sparseWire, err := sparse.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			var decodedSparse ErrorIndication
			report, err = decodedSparse.UnmarshalAPER(sparseWire, options...)
			if err != nil || len(report.Observations) != 2 {
				t.Fatalf("sparse report=%+v err=%v", report, err)
			}
			for i, path := range []aper.Path{"Extensions[0]", "Extensions[3]"} {
				check("sparse sequence", aper.DecodeReport{Observations: report.Observations[i : i+1]}, nil, aper.UnknownExtension, path, "§9.3.4")
				if origin := decodedSparse.Extensions()[i].Origin(); origin.Location.Path != path {
					t.Errorf("sparse origin=%+v want=%q", origin, path)
				}
			}
			got, err = decodedSparse.MarshalAPER()
			replay("sparse sequence", sparseWire, got, err)

			enumeration, report, err := BroadcastCodec().DecodeAPER([]byte{0x80}, options...)
			check("enumeration", report, err, aper.UnknownExtension, "Broadcast", "§14.3")
			got, err = BroadcastCodec().EncodeAPER(enumeration)
			replay("enumeration", []byte{0x80}, got, err)
			invalid := bytes.Clone(wire)
			invalid[len(invalid)-1] |= 1
			report, err = decoded.UnmarshalAPER(invalid, options...)
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || len(report.Deviations) != 1 || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0].End != uint64(len(wire))*8 {
				t.Fatalf("known addition location=%+v report=%+v err=%v", located, report, err)
			}
		})
	}
}
func receiverUnknownWire(t *testing.T, count int) []byte {
	t.Helper()
	fields := make(ErrorIndicationIEContainer, count)
	for i := range fields {
		var err error
		fields[i], err = ErrorIndicationIEs().NewOpaque(ProtocolIEID(65532-i), CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
	}
	body := ErrorIndication{ProtocolIEs: fields}
	message := InitiatingMessage{ProcedureCode: 0, Criticality: CriticalityIgnore, LppatransactionID: 7, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = 0
		*s21.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
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
			var value LPPAPDU
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
			var reused LPPAPDU
			if _, err := reused.UnmarshalAPER(valid, options...); err != nil {
				t.Fatal(err)
			}
			for _, value := range []*LPPAPDU{new(LPPAPDU), &reused} {
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
	codec := LPPAPDUCodec()
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
				if _, err := ValidateMessage(&value.Value, validationOptions...); err != nil {
					t.Error(err)
					return
				}
				if _, err := NewLPPAPDUInitiatingMessage(*value.Value.InitiatingMessage, buildOptions...); err != nil {
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
		value, report, err := BroadcastCodec().DecodeAPER([]byte{0x80}, options...)
		if err != nil || value.Value != Broadcast(2) || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("unknown enum value=%v report=%+v err=%v", value.Value, report, err)
		}
		observation := report.Observations[0]
		if observation.Kind != aper.UnknownExtension || observation.Rule.Clause != "§14.3" || !observation.Location.HasWireLocation || observation.Location.Path != "Broadcast" {
			t.Fatalf("observation=%+v", observation)
		}
		replay, err := BroadcastCodec().EncodeAPER(value)
		if err != nil || !bytes.Equal(replay, []byte{0x80}) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
		// InterRATMeasurementQuantitiesValue has the known NR addition.
		_, report, err = InterRATMeasurementQuantitiesValueCodec().DecodeAPER([]byte{0x80}, options...)
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
	var original LPPAPDU
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
				var v LPPAPDU
				_, err := v.UnmarshalAPER(wire, aper.WithLimits(limits))
				return err
			}},
			{"encode", setter.encode, func(limits aper.Limits) error {
				_, err := original.MarshalAPER(aper.WithEncodeLimits(limits))
				return err
			}},
			{"build", setter.build, func(limits aper.Limits) error {
				_, err := NewLPPAPDUInitiatingMessage(*original.InitiatingMessage, aper.WithBuildLimits(limits))
				return err
			}},
			{"validate", setter.validate, func(limits aper.Limits) error {
				_, err := ValidateMessage(&original, aper.WithValidationLimits(limits))
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
						var reused LPPAPDU
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
		var value LPPAPDU
		state := aper.ApplyDecodeOptions()
		if err := s23.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&value, wire, state); err != nil {
			t.Fatal(err)
		}
		var usages [4]aper.DecodeUsage
		usages[0] = state.Usage()
		encode, err := aper.EncodeBudget()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget(&value, encode, false); err != nil {
			t.Fatal(err)
		}
		usages[1] = aper.NewBudgetBuffer(encode).Usage()
		validate, err := aper.ValidationBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err := s24.BridgeValidateMessageBudget(&value, validate)
		if err != nil || *s09.BridgeValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget(&value, validate, false); err != nil {
			t.Fatal(err)
		}
		usages[2] = aper.NewBudgetBuffer(validate).Usage()
		build, err := aper.BuildBudget()
		if err != nil {
			t.Fatal(err)
		}
		report, err = s24.BridgeValidateMessageBudget(&value, build)
		if err != nil || *s09.BridgeValidationReportFieldErr(&report) != nil {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget(&value, build, false); err != nil {
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
		var rejected LPPAPDU
		err = s23.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&rejected, wire, failed)
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
	if s10.BridgeErrorIndicationIEValueMethodMatchesID((ErrorIndicationIEValue{}), 0, budget) {
		t.Fatal("a zero union matched id zero without an arm")
	}
}
func TestEnvelopeFindingsRespectTheSameReportCeiling(t *testing.T) {
	wire := receiverUnknownWire(t, 2)
	var value LPPAPDU
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value.InitiatingMessage.Criticality = CriticalityReject
	report, err := ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 2}))
	var located *aper.DecodeError
	if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || located.Location.Path == "" || len(report.Issues) > 2 || located.Location.HasWireLocation {
		t.Fatalf("report=%+v err=%v location=%+v", report, err, located)
	}
	if _, err := ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 3})); err != nil {
		t.Fatal(err)
	}
}
func TestPDUUnusedRootChoiceIndex(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value LPPAPDU
		report, err := value.UnmarshalAPER([]byte{0x60}, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§11.5.7.1" || !strings.Contains(string(located.Location.Path), "LPPAPDU") || len(report.Deviations) != 1 {
			t.Fatalf("unused choice: report=%+v err=%v location=%+v", report, err, located)
		}
	}
}
func TestDescriptorBuildFailuresHaveOwnedIdentity(t *testing.T) {
	body, err := NewErrorIndication(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func() error{
		func() error { _, err := ErrorIndicationProcedure().Initiating().Build(body, -1); return err },
		func() error { _, err := (ErrorIndicationInitiatingBinding{}).Build(body, 1); return err },
		func() error { _, err := (SuccessfulBinding[ErrorIndication]{}).Build(body, 1); return err },
		func() error { _, err := (UnsuccessfulBinding[ErrorIndication]{}).Build(body, 1); return err },
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
	_, err := (NewPayloadCodec[int]{}).Call(nil, nil)
	check(err, aper.ErrInvalidValue)
	_, _, err = (DecodePayload[int]{}).Call([]byte{1}, PayloadCodec[int]{}, PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	_, err = (EncodePayload[int]{}).Call(1, PayloadCodec[int]{}, PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	codec, err := (NewPayloadCodec[int]{}).Call(func(data []byte, _ PayloadLimits) (int, PayloadReport, error) {
		return len(data), PayloadReport{Deviations: []PayloadDeviation{{Path: "a"}, {Path: "b"}}}, nil
	}, func(int, PayloadLimits) ([]byte, error) { return []byte{1, 2}, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []PayloadLimits{{MaxInputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}, {MaxReports: 1}} {
		_, _, err = (DecodePayload[int]{}).Call([]byte{1, 2}, codec, limits)
		check(err, aper.ErrLimit)
	}
	for _, limits := range []PayloadLimits{{MaxOutputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}} {
		_, err = (EncodePayload[int]{}).Call(2, codec, limits)
		check(err, aper.ErrLimit)
	}
}

// TS 36.455 V19.0.0 §9.3.3/§9.3.5 declares these CHOICE roots and additions.
// X.691 (02/2021) §23.8 frames known and unknown additions alike as open types.
// The synthetic known-arm encodings were checked against upstream pycrate.
func testChoiceExtensionClassification(t *testing.T, options []aper.DecodeOption) {
	for _, row := range []struct {
		name, wire string
		choice     int
	}{
		{"BitmapsforNPRS/ten-tdd", "800100", BitmapsforNPRSChoiceTenTdd},
		{"BitmapsforNPRS/forty-tdd", "810400000000", BitmapsforNPRSChoiceFortyTdd},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			var value BitmapsforNPRS
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
				t.Errorf("known arm: report=%+v err=%v", report, err)
			}
			if value.Choice != row.choice || value.UnknownExtension != nil {
				t.Fatalf("typed arm=%+v, want choice=%d", value, row.choice)
			}
			replay, err := value.MarshalAPER(aper.WithoutReplay())
			if err != nil || !bytes.Equal(replay, wire) {
				t.Errorf("known replay=%x want=%x err=%v", replay, wire, err)
			}
		})
	}
	for _, row := range []struct {
		name, wire string
		choice     int
	}{
		{"InterRATMeasuredResultsValue/resultNR", "80050000000000", InterRATMeasuredResultsValueChoiceResultNR},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			var value InterRATMeasuredResultsValue
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
				t.Errorf("known arm: report=%+v err=%v", report, err)
			}
			if value.Choice != row.choice || value.UnknownExtension != nil {
				t.Fatalf("typed arm=%+v, want choice=%d", value, row.choice)
			}
			replay, err := value.MarshalAPER(aper.WithoutReplay())
			if err != nil || !bytes.Equal(replay, wire) {
				t.Errorf("known replay=%x want=%x err=%v", replay, wire, err)
			}
		})
	}
	for _, row := range []struct {
		name, wire string
		choice     int
	}{
		{"OTDOACell-Information-Item/pRSMutingConfiguration", "800100", OTDOACellInformationItemChoicePRSMutingConfiguration},
		{"OTDOACell-Information-Item/prsid", "8103000000", OTDOACellInformationItemChoicePrsid},
		{"OTDOACell-Information-Item/tpid", "8203000000", OTDOACellInformationItemChoiceTpid},
		{"OTDOACell-Information-Item/tpType", "830100", OTDOACellInformationItemChoiceTpType},
		{"OTDOACell-Information-Item/numberOfDlFrames-Extended", "84020000", OTDOACellInformationItemChoiceNumberOfDlFramesExtended},
		{"OTDOACell-Information-Item/crsCPlength", "850100", OTDOACellInformationItemChoiceCrsCPlength},
		{"OTDOACell-Information-Item/mBSFNsubframeConfiguration", "86020000", OTDOACellInformationItemChoiceMBSFNsubframeConfiguration},
		{"OTDOACell-Information-Item/nPRSConfiguration", "870100", OTDOACellInformationItemChoiceNPRSConfiguration},
		{"OTDOACell-Information-Item/offsetNBChanneltoEARFCN", "880100", OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN},
		{"OTDOACell-Information-Item/operationModeInfo", "890100", OTDOACellInformationItemChoiceOperationModeInfo},
		{"OTDOACell-Information-Item/nPRS-ID", "8a03000000", OTDOACellInformationItemChoiceNPRSID},
		{"OTDOACell-Information-Item/dL-Bandwidth", "8b0100", OTDOACellInformationItemChoiceDLBandwidth},
		{"OTDOACell-Information-Item/pRSOccasionGroup", "8c0100", OTDOACellInformationItemChoicePRSOccasionGroup},
		{"OTDOACell-Information-Item/pRSFreqHoppingConfig", "8d020000", OTDOACellInformationItemChoicePRSFreqHoppingConfig},
		{"OTDOACell-Information-Item/repetitionNumberofSIB1-NB", "8e0100", OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB},
		{"OTDOACell-Information-Item/nPRSSequenceInfo", "8f020000", OTDOACellInformationItemChoiceNPRSSequenceInfo},
		{"OTDOACell-Information-Item/nPRSType2", "900100", OTDOACellInformationItemChoiceNPRSType2},
		{"OTDOACell-Information-Item/tddConfiguration", "910100", OTDOACellInformationItemChoiceTddConfiguration},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			var value OTDOACellInformationItem
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
				t.Errorf("known arm: report=%+v err=%v", report, err)
			}
			if value.Choice != row.choice || value.UnknownExtension != nil {
				t.Fatalf("typed arm=%+v, want choice=%d", value, row.choice)
			}
			replay, err := value.MarshalAPER(aper.WithoutReplay())
			if err != nil || !bytes.Equal(replay, wire) {
				t.Errorf("known replay=%x want=%x err=%v", replay, wire, err)
			}
		})
	}
	for _, row := range []struct {
		name, wire string
		choice     int
	}{
		{"PRSMutingConfiguration/thirty-two", "800400000000", PRSMutingConfigurationChoiceThirtyTwo},
		{"PRSMutingConfiguration/sixty-four", "81080000000000000000", PRSMutingConfigurationChoiceSixtyFour},
		{"PRSMutingConfiguration/one-hundred-and-twenty-eight", "821000000000000000000000000000000000", PRSMutingConfigurationChoiceOneHundredAndTwentyEight},
		{"PRSMutingConfiguration/two-hundred-and-fifty-six", "83200000000000000000000000000000000000000000000000000000000000000000", PRSMutingConfigurationChoiceTwoHundredAndFiftySix},
		{"PRSMutingConfiguration/five-hundred-and-twelve", "844000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", PRSMutingConfigurationChoiceFiveHundredAndTwelve},
		{"PRSMutingConfiguration/one-thousand-and-twenty-four", "8580800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", PRSMutingConfigurationChoiceOneThousandAndTwentyFour},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			var value PRSMutingConfiguration
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
				t.Errorf("known arm: report=%+v err=%v", report, err)
			}
			if value.Choice != row.choice || value.UnknownExtension != nil {
				t.Fatalf("typed arm=%+v, want choice=%d", value, row.choice)
			}
			replay, err := value.MarshalAPER(aper.WithoutReplay())
			if err != nil || !bytes.Equal(replay, wire) {
				t.Errorf("known replay=%x want=%x err=%v", replay, wire, err)
			}
		})
	}

	for _, row := range []struct {
		name  string
		known byte
		value interface {
			UnmarshalAPER([]byte, ...aper.DecodeOption) (aper.DecodeReport, error)
			MarshalAPER(...aper.EncodeOption) ([]byte, error)
		}
	}{
		{"BitmapsforNPRS/unknown", 2, &BitmapsforNPRS{}},
		{"Cause/unknown", 0, &Cause{}},
		{"InterRATMeasuredResultsValue/unknown", 1, &InterRATMeasuredResultsValue{}},
		{"MeasuredResultsValue/unknown", 0, &MeasuredResultsValue{}},
		{"NPRSMutingConfiguration/unknown", 0, &NPRSMutingConfiguration{}},
		{"OTDOACell-Information-Item/unknown", 18, &OTDOACellInformationItem{}},
		{"PRSMutingConfiguration/unknown", 6, &PRSMutingConfiguration{}},
		{"LPPA-PDU/unknown", 0, &LPPAPDU{}},
	} {
		t.Run(row.name, func(t *testing.T) {
			// All pinned counts fit X.691 §11.6's short normally-small form.
			wire := []byte{0x80 | row.known, 1, 0xa5}
			report, err := row.value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
				t.Fatalf("unknown: report=%+v err=%v", report, err)
			}
			observation := report.Observations[0]
			if observation.Kind != aper.UnknownExtension || observation.Location.Path != "UnknownExtension" || observation.Rule != (aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§23.8"}) || !observation.Location.HasWireLocation || len(observation.Location.Spans) != 1 || observation.Location.Spans[0] != (aper.BitSpan{Start: 8, End: 24}) {
				t.Errorf("unknown observation=%+v", observation)
			}
			replay, err := row.value.MarshalAPER()
			if err != nil || !bytes.Equal(replay, wire) {
				t.Errorf("unknown replay=%x want=%x err=%v", replay, wire, err)
			}
		})
	}
}
