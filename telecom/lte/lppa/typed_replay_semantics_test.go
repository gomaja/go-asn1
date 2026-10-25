package lppa

import (
	"bytes"
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
	"testing"
)

func TestReplayMutableSourceContents(t *testing.T) {
	t.Run("octets", func(t *testing.T) {
		pLMNIdentitySemanticEditRestore(t, PLMNIdentityCodec(), PLMNIdentity{1, 2, 3}, func(v *PLMNIdentity) { (*v)[1] = 9 }, func(v *PLMNIdentity) { (*v)[1] = 2 })
	})
	t.Run("octet-length", func(t *testing.T) {
		sSIDSemanticEditRestore(t, SSIDCodec(), SSID{1}, func(v *SSID) { *v = append(*v, 2) }, func(v *SSID) { *v = (*v)[:1] })
	})
	t.Run("integer", func(t *testing.T) {
		initial := new(big.Int).Lsh(big.NewInt(1), 130)
		measurementIDSemanticEditRestore(t, MeasurementIDCodec(), initial, func(v **big.Int) { (*v).Add(*v, big.NewInt(7)) }, func(v **big.Int) { (*v).Sub(*v, big.NewInt(7)) })
	})
	t.Run("bits", func(t *testing.T) {
		eUTRANCellIdentifierSemanticEditRestore(t, EUTRANCellIdentifierCodec(), runtime.BitString{Bytes: []byte{0xa0, 0, 0, 0}, BitLength: 28}, func(v *runtime.BitString) { v.Bytes[0] = 0xb0 }, func(v *runtime.BitString) { v.Bytes[0] = 0xa0 })
	})
}
func TestReplayInsignificantBitStorage(t *testing.T) {
	c := EUTRANCellIdentifierCodec()
	encoder := *s00.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c)
	calls := 0
	*s00.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&c) = func(v runtime.BitString, f bool, b *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, f, b)
	}
	wire := sliceByteReplayMust(c.EncodeAPER(eUTRANCellIdentifierAPERValueReplayMust(c.New(runtime.BitString{Bytes: []byte{0xa0, 0, 0, 0}, BitLength: 28}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	v.Value.Bytes[3] |= 15
	v.Value.Bytes = append(v.Value.Bytes, 255)
	if got := sliceByteReplayMust(c.EncodeAPER(v)); !bytes.Equal(got, wire) || calls != 0 {
		t.Fatal("unused backing bits or octets reached encoder")
	}
	v.Value.BitLength = 29
	if _, err := c.EncodeAPER(v); err == nil {
		t.Fatal("invalid significant length replayed")
	}
}
func TestReplayOptionalPresence(t *testing.T) {
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
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restored optional presence changed replay")
	}
}
func TestReplayUnknownAdditionRestoration(t *testing.T) {
	v := CriticalityDiagnostics{}
	if err := v.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s09.BridgeCriticalityDiagnosticsFieldExtCount(&v) = 3
	*s09.BridgeCriticalityDiagnosticsFieldExtPresent(&v) = append(*s09.BridgeCriticalityDiagnosticsFieldExtPresent(&v), false, false, false)
	*s09.BridgeCriticalityDiagnosticsFieldExtData(&v) = append(*s09.BridgeCriticalityDiagnosticsFieldExtData(&v), nil, nil, nil)
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
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restored addition lost received bitmap")
	}
	if fresh := sliceByteReplayMust(decoded.MarshalAPER(aper.WithoutReplay())); bytes.Equal(fresh, wire) {
		t.Fatal("fixture has no nonpreferred bitmap")
	}
}
func TestReplayNestedWithoutReplayBeforeFraming(t *testing.T) {
	item := ResultNRItem{}
	if err := item.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s19.BridgeResultNRItemFieldExtCount(&item) = 3
	*s19.BridgeResultNRItemFieldExtPresent(&item) = append(*s19.BridgeResultNRItemFieldExtPresent(&item), false, false, false)
	*s19.BridgeResultNRItemFieldExtData(&item) = append(*s19.BridgeResultNRItemFieldExtData(&item), nil, nil, nil)
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
	want := sliceByteReplayMust(original.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("received parent replayed nested fresh copy")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("fresh copy changed original")
	}
}
func TestReplayStrictPaddingHookFreshCopy(t *testing.T) {
	wire := sliceByteReplayMust(hex.DecodeString("00020000010d00000200020001300003000140"))
	var original LPPAPDU
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	// X.691 (02/2021) §11.1.4 refuses the nonzero received padding on public decode.
	// Internal received-form hooks exercise fresh copies independently of that refusal.
	nonpreferred := bytes.Clone(wire)
	nonpreferred[len(nonpreferred)-1] = 0x4f
	*s23.BridgeLPPAPDUFieldReceivedBytes(&original) = aper.OriginalWire(nonpreferred)
	body, _ := original.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	*s21.BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(&body.ProtocolIEs[1].Value) = aper.OriginalWire([]byte{0x4f})
	if got := sliceByteReplayMust(original.MarshalAPER()); !bytes.Equal(got, nonpreferred) {
		t.Fatal("hook did not replay")
	}
	fresh := sliceByteReplayMust(original.MarshalAPER(aper.WithoutReplay()))
	copy := original.WithoutReplay()
	if got := sliceByteReplayMust(copy.MarshalAPER()); !bytes.Equal(got, fresh) || !bytes.Equal(got, wire) {
		t.Fatal("fresh copy failed to reach nested values")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !bytes.Equal(got, nonpreferred) {
		t.Fatal("fresh copy altered original")
	}
}
func replayGrowthWire(t *testing.T, n int) []byte {
	t.Helper()
	field := eCIDMeasurementInitiationRequestIEFieldReplayMust(ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().New(ReportCharacteristics(1)))
	body := ECIDMeasurementInitiationRequest{ProtocolIEs: make(ECIDMeasurementInitiationRequestIEContainer, n)}
	for i := range body.ProtocolIEs {
		body.ProtocolIEs[i] = field
	}
	return sliceByteReplayMust(body.MarshalAPER())
}
func TestReplayEditedLeafGrowthLinear(t *testing.T) {
	var previous float64
	for _, n := range []int{8, 16, 32, 64, 128} {
		wire := replayGrowthWire(t, n)
		count := testing.AllocsPerRun(20, func() {
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
func TestReplayCopiesAndForeignOwners(t *testing.T) {
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
	want := sliceByteReplayMust(first.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("copied source occurrence hid edit")
	}
	first.ProtocolIEs[0] = second.ProtocolIEs[0]
	got = sliceByteReplayMust(first.MarshalAPER())
	want = sliceByteReplayMust(first.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) {
		t.Fatal("foreign owner restarted comparison")
	}
}
func TestReplayFragmentedOpaquePreservation(t *testing.T) {
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
	if !ok || !bytes.Equal(opaque.Bytes(), payload) {
		t.Fatal("edited framing lost opaque fragmented payload")
	}
	decoded.ProtocolIEs[0].Criticality = CriticalityIgnore
	if got := sliceByteReplayMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restored fragmented value changed replay")
	}
}
func TestReplayCompatibleCodecContext(t *testing.T) {
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
		*s00.BridgeLPPATransactionIDAPERValueFieldReceived(&sealed) = *s01.BridgeProcedureCodeAPERValueFieldReceived(&decoded)
		*s00.BridgeLPPATransactionIDAPERValueFieldReplay(&sealed) = *s01.BridgeProcedureCodeAPERValueFieldReplay(&decoded)
		*s00.BridgeLPPATransactionIDAPERValueFieldContext(&sealed) = *s01.BridgeProcedureCodeAPERValueFieldContext(&decoded)
		return sealed
	}()
	got := sliceByteReplayMust(b.EncodeAPER(value))
	want := sliceByteReplayMust(b.EncodeAPER(value, aper.WithoutReplay()))
	if !bytes.Equal(got, want) || bytes.Equal(got, []byte{7}) {
		t.Fatalf("wrong-context replay=%x want=%x", got, want)
	}
}
func TestReplayComparisonHonorsCurrentGraphLimits(t *testing.T) {
	wire := replayGrowthWire(t, 8)
	var value ECIDMeasurementInitiationRequest
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value.ProtocolIEs = append(value.ProtocolIEs, value.ProtocolIEs...)
	if _, err := value.MarshalAPER(aper.WithEncodeLimits(aper.Limits{MaxElements: 10})); err == nil {
		t.Fatal("comparison ignored edited graph element ceiling")
	}
	if _, err := value.MarshalAPER(aper.WithEncodeLimits(aper.Limits{MaxWork: 1050})); err == nil {
		t.Fatal("comparison ignored call work ceiling")
	}
}
func TestReplayListItemGrowthLinear(t *testing.T) {
	var previous float64
	for _, n := range []int{2, 4, 8, 16, 32} {
		body := ResultNRComplete{Value: make(ResultNR, n)}
		wire := sliceByteReplayMust(body.MarshalAPER())
		count := testing.AllocsPerRun(20, func() {
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
func TestReplaySelectedChildrenRetainOpenScope(t *testing.T) {
	diagnostics := CriticalityDiagnostics{}
	if err := diagnostics.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(diagnostics))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
	message := InitiatingMessage{ProcedureCode: 0, Criticality: CriticalityIgnore, Value: func() InitiatingValue {
		sealed := InitiatingValue{}
		*s21.BridgeInitiatingValueFieldCode(&sealed) = 0
		*s21.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
		return sealed
	}()}
	pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
	wire := sliceByteReplayMust(pdu.MarshalAPER())
	state := aper.ApplyDecodeOptions()
	var decoded LPPAPDU
	if err := s23.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&decoded, wire, state); err != nil {
		t.Fatal(err)
	}
	if got := state.Usage().MaxOpenTypeDepth; got != 3 {
		t.Fatalf("selected nested depth=%d want 3", got)
	}
}
func TestReplayUnionFreshCopyBeforeParentFraming(t *testing.T) {
	diagnostics := CriticalityDiagnostics{}
	if err := diagnostics.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s09.BridgeCriticalityDiagnosticsFieldExtCount(&diagnostics) = 3
	*s09.BridgeCriticalityDiagnosticsFieldExtPresent(&diagnostics) = append(*s09.BridgeCriticalityDiagnosticsFieldExtPresent(&diagnostics), false, false, false)
	*s09.BridgeCriticalityDiagnosticsFieldExtData(&diagnostics) = append(*s09.BridgeCriticalityDiagnosticsFieldExtData(&diagnostics), nil, nil, nil)
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
	want := sliceByteReplayMust(original.MarshalAPER(aper.WithoutReplay()))
	if got := sliceByteReplayMust(copy.MarshalAPER()); !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("table union fresh copy did not reach parent framing")
	}
	if got := sliceByteReplayMust(original.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("union fresh copy changed original")
	}
}
func TestReplayLargeUnchangedAllocatesOnlyResult(t *testing.T) {
	wire := replayGrowthWire(t, 128)
	var value ECIDMeasurementInitiationRequest
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if count := testing.AllocsPerRun(50, func() {
		got, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(got, wire) {
			panic("unchanged replay")
		}
	}); count != 1 {
		t.Fatalf("unchanged large root allocates %.0f want only result", count)
	}
}
