package lppa

import (
	q16 "bytes"
	q20 "encoding/hex"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	bridge5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	bridge2 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	bridge4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	bridge6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	bridge3 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q12 "math/big"
	q8 "testing"
)

func TestReplayMutableSourceContents(t *q8.T) {
	t.Run("octets", func(t *q8.T) {
		pLMNIdentitySemanticEditRestore(t, PLMNIdentityCodec(), PLMNIdentity{1, 2, 3}, func(v *PLMNIdentity) { (*v)[1] = 9 }, func(v *PLMNIdentity) { (*v)[1] = 2 })
	})
	t.Run("octet-length", func(t *q8.T) {
		sSIDSemanticEditRestore(t, SSIDCodec(), SSID{1}, func(v *SSID) { *v = append(*v, 2) }, func(v *SSID) { *v = (*v)[:1] })
	})
	t.Run("integer", func(t *q8.T) {
		initial := new(q12.Int).Lsh(q12.NewInt(1), 130)
		measurementIDSemanticEditRestore(t, MeasurementIDCodec(), initial, func(v **q12.Int) { (*v).Add(*v, q12.NewInt(7)) }, func(v **q12.Int) { (*v).Sub(*v, q12.NewInt(7)) })
	})
	t.Run("bits", func(t *q8.T) {
		eUTRANCellIdentifierSemanticEditRestore(t, EUTRANCellIdentifierCodec(), q14.BitString{Bytes: []byte{0xa0, 0, 0, 0}, BitLength: 28}, func(v *q14.BitString) { v.Bytes[0] = 0xb0 }, func(v *q14.BitString) { v.Bytes[0] = 0xa0 })
	})
}
func TestReplayInsignificantBitStorage(t *q8.T) {
	c := EUTRANCellIdentifierCodec()
	encoder := *bridge0.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c)
	calls := 0
	*bridge0.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c) = func(v q14.BitString, f bool, b *q15.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(eUTRANCellIdentifierAPERValueReplayMust(c.New(q14.BitString{Bytes: []byte{0xa0, 0, 0, 0}, BitLength: 28}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	v.Value.Bytes[3] |= 15
	v.Value.Bytes = append(v.Value.Bytes, 255)
	if got := sliceByteReplayMust(c.EncodeAPER(v)); !q16.Equal(got, wire) || calls != 0 {
		t.Fatal("unused backing bits or octets reached encoder")
	}
	v.Value.BitLength = 29
	if _, err := c.EncodeAPER(v); err == nil {
		t.Fatal("invalid significant length replayed")
	}
}
func TestReplayOptionalPresence(t *q8.T) {
	v := CriticalityDiagnostics{}
	wire := sliceByteReplayMust(v.MarshalAPER())
	var decoded CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	decoded.IEExtensions = CriticalityDiagnosticsExtIEsExtContainer{}
	if _, err := decoded.MarshalAPER(); err == nil {
		t.Fatal("optional present empty replayed as absent")
	}
	decoded.IEExtensions = nil
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !q16.Equal(got, wire) {
		t.Fatal("restored optional presence changed replay")
	}
}
func TestReplayUnknownAdditionRestoration(t *q8.T) {
	v := CriticalityDiagnostics{}
	if err := v.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*bridge1.BridgeCriticalityDiagnosticsFieldExtCount(&v) = 3
	*bridge1.BridgeCriticalityDiagnosticsFieldExtPresent(&v) = append(*bridge1.BridgeCriticalityDiagnosticsFieldExtPresent(&v), false, false, false)
	*bridge1.BridgeCriticalityDiagnosticsFieldExtData(&v) = append(*bridge1.BridgeCriticalityDiagnosticsFieldExtData(&v), nil, nil, nil)
	wire := sliceByteReplayMust(v.MarshalAPER())
	var decoded CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if err := decoded.RemoveExtension(0); err != nil {
		t.Fatal(err)
	}
	if err := decoded.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !q16.Equal(got, wire) {
		t.Fatal("restored addition lost received bitmap")
	}
	if fresh := sliceByteReplayMust(decoded.MarshalAPER(q15.WithoutReplay())); q16.Equal(fresh, wire) {
		t.Fatal("fixture has no nonpreferred bitmap")
	}
}
func TestReplayNestedWithoutReplayBeforeFraming(t *q8.T) {
	item := ResultNRItem{}
	if err := item.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*bridge2.BridgeResultNRItemFieldExtCount(&item) = 3
	*bridge2.BridgeResultNRItemFieldExtPresent(&item) = append(*bridge2.BridgeResultNRItemFieldExtPresent(&item), false, false, false)
	*bridge2.BridgeResultNRItemFieldExtData(&item) = append(*bridge2.BridgeResultNRItemFieldExtData(&item), nil, nil, nil)
	outer := ResultNRComplete{Value: ResultNR{item}}
	wire := sliceByteReplayMust(outer.MarshalAPER())
	var original ResultNRComplete
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	copy := original
	copy.Value = append(ResultNR(nil), original.Value...)
	copy.Value[0] = copy.Value[0].WithoutReplay()
	got := sliceByteReplayMust(copy.MarshalAPER())
	want := sliceByteReplayMust(original.MarshalAPER(q15.WithoutReplay()))
	if !q16.Equal(got, want) || q16.Equal(got, wire) {
		t.Fatal("received parent replayed nested fresh copy")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !q16.Equal(got, wire) {
		t.Fatal("fresh copy changed original")
	}
}
func TestReplayStrictPaddingHookFreshCopy(t *q8.T) {
	wire := sliceByteReplayMust(q20.DecodeString("00020000010d00000200020001300003000140"))
	var original LPPAPDU
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	// X.691 (02/2021) §11.1.4 refuses the nonzero received padding on public decode.
	// Internal received-form hooks exercise fresh copies independently of that refusal.
	nonpreferred := q16.Clone(wire)
	nonpreferred[len(nonpreferred)-1] = 0x4f
	*bridge3.BridgeLPPAPDUFieldReceivedBytes(&original) = q15.OriginalWire(nonpreferred)
	body, _ := original.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	*bridge4.BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(&body.ProtocolIEs[1].Value) = q15.OriginalWire([]byte{0x4f})
	if got := sliceByteReplayMust(original.MarshalAPER()); !q16.Equal(got, nonpreferred) {
		t.Fatal("hook did not replay")
	}
	fresh := sliceByteReplayMust(original.MarshalAPER(q15.WithoutReplay()))
	copy := original.WithoutReplay()
	if got := sliceByteReplayMust(copy.MarshalAPER()); !q16.Equal(got, fresh) || !q16.Equal(got, wire) {
		t.Fatal("fresh copy failed to reach nested values")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !q16.Equal(got, nonpreferred) {
		t.Fatal("fresh copy altered original")
	}
}
func replayGrowthWire(t *q8.T, n int) []byte {
	t.Helper()
	field := eCIDMeasurementInitiationRequestIEFieldReplayMust(ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().New(ReportCharacteristics(1)))
	body := ECIDMeasurementInitiationRequest{ProtocolIEs: make(ECIDMeasurementInitiationRequestIEContainer, n)}
	for i := range body.ProtocolIEs {
		body.ProtocolIEs[i] = field
	}
	return sliceByteReplayMust(body.MarshalAPER())
}
func TestReplayEditedLeafGrowthLinear(t *q8.T) {
	var previous float64
	for _, n := range []int{8, 16, 32, 64, 128} {
		wire := replayGrowthWire(t, n)
		count := q8.AllocsPerRun(20, func() {
			var v ECIDMeasurementInitiationRequest
			if _, err := v.UnmarshalAPER(wire); err != nil {
				panic(err)
			}
			leaf, ok := v.ProtocolIEs[len(v.ProtocolIEs)-1].Value.AsReportCharacteristics()
			if !ok {
				panic("lost typed leaf")
			}
			*leaf = ReportCharacteristics(0)
			if _, err := v.MarshalAPER(); err != nil {
				panic(err)
			}
		})
		t.Logf("items=%d decode/edit/encode allocations=%.0f", n, count)
		if previous > 0 && count > previous*2.25 {
			t.Fatalf("nonlinear growth: %.0f / %.0f", count, previous)
		}
		previous = count
	}
}
func TestReplayCopiesAndForeignOwners(t *q8.T) {
	wire := replayGrowthWire(t, 2)
	var first, second ECIDMeasurementInitiationRequest
	if _, err := first.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := second.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	// The same snapshot can occur more than once, without hiding an edited copy.
	first.ProtocolIEs[0] = first.ProtocolIEs[1]
	leaf, _ := first.ProtocolIEs[0].Value.AsReportCharacteristics()
	*leaf = 0
	got := sliceByteReplayMust(first.MarshalAPER())
	want := sliceByteReplayMust(first.MarshalAPER(q15.WithoutReplay()))
	if !q16.Equal(got, want) || q16.Equal(got, wire) {
		t.Fatal("copied source occurrence hid edit")
	}
	first.ProtocolIEs[0] = second.ProtocolIEs[0]
	got = sliceByteReplayMust(first.MarshalAPER())
	want = sliceByteReplayMust(first.MarshalAPER(q15.WithoutReplay()))
	if !q16.Equal(got, want) {
		t.Fatal("foreign owner restarted comparison")
	}
}
func TestReplayFragmentedOpaquePreservation(t *q8.T) {
	payload := make([]byte, 65540)
	for i := range payload {
		payload[i] = byte(i*13 + 7)
	}
	field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, payload))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	wire := sliceByteReplayMust(body.MarshalAPER())
	var decoded ErrorIndication
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	decoded.ProtocolIEs[0].Criticality = CriticalityNotify
	changed := sliceByteReplayMust(decoded.MarshalAPER())
	var again ErrorIndication
	if _, err := again.UnmarshalAPER(changed); err != nil {
		t.Fatal(err)
	}
	opaque, ok := again.ProtocolIEs[0].Value.Opaque()
	if !ok || !q16.Equal(opaque.Bytes(), payload) {
		t.Fatal("edited framing lost opaque fragmented payload")
	}
	decoded.ProtocolIEs[0].Criticality = CriticalityIgnore
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !q16.Equal(got, wire) {
		t.Fatal("restored fragmented value changed replay")
	}
}
func TestReplayCompatibleCodecContext(t *q8.T) {
	a := ProcedureCodeCodec()
	b := LPPATransactionIDCodec()
	decoded, _, err := a.DecodeAPER([]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	// The concrete codecs have different source-named holders. Preserve the
	// foreign context explicitly to keep exercising the context refusal.
	value := func() LPPATransactionIDAPERValue {
		sealed := LPPATransactionIDAPERValue{Value: decoded.Value}
		*bridge0.BridgeLPPATransactionIDAPERValueFieldReceived(&sealed) = *bridge5.BridgeProcedureCodeAPERValueFieldReceived(&decoded)
		*bridge0.BridgeLPPATransactionIDAPERValueFieldReplay(&sealed) = *bridge5.BridgeProcedureCodeAPERValueFieldReplay(&decoded)
		*bridge0.BridgeLPPATransactionIDAPERValueFieldContext(&sealed) = *bridge5.BridgeProcedureCodeAPERValueFieldContext(&decoded)
		return sealed
	}()
	got := sliceByteReplayMust(b.EncodeAPER(value))
	want := sliceByteReplayMust(b.EncodeAPER(value, q15.WithoutReplay()))
	if !q16.Equal(got, want) || q16.Equal(got, []byte{7}) {
		t.Fatalf("wrong-context replay=%x want=%x", got, want)
	}
}
func TestReplayComparisonHonorsCurrentGraphLimits(t *q8.T) {
	wire := replayGrowthWire(t, 8)
	var value ECIDMeasurementInitiationRequest
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value.ProtocolIEs = append(value.ProtocolIEs, value.ProtocolIEs...)
	if _, err := value.MarshalAPER(q15.WithEncodeLimits(q15.Limits{MaxElements: 10})); err == nil {
		t.Fatal("comparison ignored edited graph element ceiling")
	}
	if _, err := value.MarshalAPER(q15.WithEncodeLimits(q15.Limits{MaxWork: 1050})); err == nil {
		t.Fatal("comparison ignored call work ceiling")
	}
}
func TestReplayListItemGrowthLinear(t *q8.T) {
	var previous float64
	for _, n := range []int{2, 4, 8, 16, 32} {
		body := ResultNRComplete{Value: make(ResultNR, n)}
		wire := sliceByteReplayMust(body.MarshalAPER())
		count := q8.AllocsPerRun(20, func() {
			var v ResultNRComplete
			if _, err := v.UnmarshalAPER(wire); err != nil {
				panic(err)
			}
			v.Value[len(v.Value)-1].NRPCI = 1
			if _, err := v.MarshalAPER(); err != nil {
				panic(err)
			}
		})
		t.Logf("list items=%d decode/edit/encode allocations=%.0f", n, count)
		if previous > 0 && count > previous*2.25 {
			t.Fatalf("nonlinear list growth: %.0f / %.0f", count, previous)
		}
		previous = count
	}
}
func TestReplaySelectedChildrenRetainOpenScope(t *q8.T) {
	diagnostics := CriticalityDiagnostics{}
	if err := diagnostics.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(diagnostics))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	message := InitiatingMessage{ProcedureCode: 0, Criticality: CriticalityIgnore, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*bridge6.BridgeInitiatingValueFieldCode(&sealed) = 0
		*bridge6.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	wire := sliceByteReplayMust(pdu.MarshalAPER())
	state := q15.ApplyDecodeOptions()
	var decoded LPPAPDU
	if err := bridge3.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&decoded, wire, state); err != nil {
		t.Fatal(err)
	}
	if got := state.Usage().MaxOpenTypeDepth; got != 3 {
		t.Fatalf("selected nested depth=%d want 3", got)
	}
}
func TestReplayUnionFreshCopyBeforeParentFraming(t *q8.T) {
	diagnostics := CriticalityDiagnostics{}
	if err := diagnostics.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*bridge1.BridgeCriticalityDiagnosticsFieldExtCount(&diagnostics) = 3
	*bridge1.BridgeCriticalityDiagnosticsFieldExtPresent(&diagnostics) = append(*bridge1.BridgeCriticalityDiagnosticsFieldExtPresent(&diagnostics), false, false, false)
	*bridge1.BridgeCriticalityDiagnosticsFieldExtData(&diagnostics) = append(*bridge1.BridgeCriticalityDiagnosticsFieldExtData(&diagnostics), nil, nil, nil)
	field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(diagnostics))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	wire := sliceByteReplayMust(body.MarshalAPER())
	var original ErrorIndication
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	copy := original
	copy.ProtocolIEs = append(ErrorIndicationIEContainer(nil), original.ProtocolIEs...)
	copy.ProtocolIEs[0].Value = copy.ProtocolIEs[0].Value.WithoutReplay()
	want := sliceByteReplayMust(original.MarshalAPER(q15.WithoutReplay()))
	if got := sliceByteReplayMust(copy.MarshalAPER()); !q16.Equal(got, want) || q16.Equal(got, wire) {
		t.Fatal("table union fresh copy did not reach parent framing")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !q16.Equal(got, wire) {
		t.Fatal("union fresh copy changed original")
	}
}
func TestReplayLargeUnchangedAllocatesOnlyResult(t *q8.T) {
	wire := replayGrowthWire(t, 128)
	var value ECIDMeasurementInitiationRequest
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if count := q8.AllocsPerRun(50, func() {
		got, err := value.MarshalAPER()
		if err != nil || !q16.Equal(got, wire) {
			panic("unchanged replay")
		}
	}); count != 1 {
		t.Fatalf("unchanged large root allocates %.0f want only result", count)
	}
}
