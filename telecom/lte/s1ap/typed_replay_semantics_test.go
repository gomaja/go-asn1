// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
	testing "testing"
)

func TestCompleteReplayMutableContents(t *testing.T) {
	t.Run("octets", func(t *testing.T) {
		nASPDUSemanticEditRestore(t, s53.NASPDUCodec(), []byte{1, 2, 3}, func(v *[]byte) { (*v)[1] = 9 }, func(v *[]byte) { (*v)[1] = 2 })
	})
	t.Run("bits", func(t *testing.T) {
		transportLayerAddressSemanticEditRestore(t, s37.TransportLayerAddressCodec(), runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}, func(v *runtime.BitString) { v.Bytes[0] = 0xb0 }, func(v *runtime.BitString) { v.Bytes[0] = 0xa0 })
	})
	t.Run("bit-length", func(t *testing.T) {
		transportLayerAddressSemanticEditRestore(t, s37.TransportLayerAddressCodec(), runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}, func(v *runtime.BitString) { v.BitLength = 5 }, func(v *runtime.BitString) { v.BitLength = 4 })
	})
	t.Run("integer", func(t *testing.T) {
		n := new(big.Int).Lsh(big.NewInt(1), 130)
		eHRPDSectorCapacityClassValueSemanticEditRestore(t, s02.EHRPDSectorCapacityClassValueCodec(), n, func(v **big.Int) { (*v).Add(*v, big.NewInt(7)) }, func(v **big.Int) { (*v).Sub(*v, big.NewInt(7)) })
	})
}
func TestValueDecodeAndUnchangedEncodeCallNoEncoder(t *testing.T) {
	calls := 0
	c := Int64ValueCodec{
		decode: func(data []byte, _ aper.DecodeState) (int64, error) { return int64(data[0]), nil },
		encode: func(v int64, _ bool, _ *aper.DecodeBudget) ([]byte, error) { calls++; return []byte{byte(v)}, nil },
		capture: func(v int64, options aper.DecodeState) (int64, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s.Uint(uint64(v))
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		},
		compare: func(v int64, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s.Uint(uint64(v))
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		},
	}
	v, _, err := c.DecodeAPER([]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called encoder")
	}
	got := sliceByteFreshMust(c.EncodeAPER(v))
	if calls != 0 || !bytes.Equal(got, []byte{42}) {
		t.Fatal("unchanged encode called encoder")
	}
	got[0] = 9
	if sliceByteFreshMust(c.EncodeAPER(v))[0] != 42 {
		t.Fatal("unchanged encode returned original storage")
	}
	v.Value = 43
	if sliceByteFreshMust(c.EncodeAPER(v))[0] != 43 || calls != 1 {
		t.Fatal("edited encode did not use encoder once")
	}
	v.Value = 42
	if sliceByteFreshMust(c.EncodeAPER(v))[0] != 42 || calls != 1 {
		t.Fatal("restore called encoder")
	}
	sliceByteFreshMust(c.EncodeAPER(v.WithoutReplay()))
	if calls != 2 {
		t.Fatal("fresh copy did not request encoder")
	}
}
func TestReplayReplacementAndCopyGraphs(t *testing.T) {
	field := tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: []byte{1, 2, 3}, TAC: []byte{4, 5}}}))
	codec := s42.TAIItemIEValueIETableCodec(s42.TAIItemIEs().Table(), aper.ListBounds{Lower: 1, Upper: 256})
	wire := sliceByteFreshMust(codec.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(codec.New(s42.TAIItemIEContainer{field, field}))))
	a, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	a.Value[0] = b.Value[0] // a replacement with a different immutable owner
	a.Value[1] = a.Value[0] // copies retain one baseline ID; neither hides an edit
	leaf, _ := a.Value[0].Value.AsTAIItem()
	leaf.TAI.TAC[0] = 9
	edited := sliceByteFreshMust(codec.EncodeAPER(a))
	var want s42.TAIItemIEContainer
	want = append(want, a.Value...)
	preferred := sliceByteFreshMust(codec.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(codec.New(want)), aper.WithoutReplay()))
	if !bytes.Equal(edited, preferred) {
		t.Fatal("replacement/copy graph lost a leaf edit")
	}
	leaf.TAI.TAC[0] = 4
	if got := sliceByteFreshMust(codec.EncodeAPER(a)); !bytes.Equal(got, wire) {
		t.Fatal("restored replacement graph did not replay")
	}
	// A fresh request must be observed even when its semantics equal the baseline.
	leaf.TAI = leaf.TAI.WithoutReplay()
	if got, want := sliceByteFreshMust(codec.EncodeAPER(a)), sliceByteFreshMust(codec.EncodeAPER(a, aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatal("copied replacement hid nested fresh request")
	}
}
func TestEditedLeafAllocationGrowthIsLinear(t *testing.T) {
	measure := func(n int) float64 {
		field := tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: []byte{1, 2, 3}, TAC: []byte{4, 5}}}))
		fields := make(s42.TAIItemIEContainer, n)
		for i := range fields {
			fields[i] = field
		}
		codec := s42.TAIItemIEValueIETableCodec(s42.TAIItemIEs().Table(), aper.ListBounds{Lower: 1, Upper: 256})
		wire := sliceByteFreshMust(codec.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(codec.New(fields))))
		return testing.AllocsPerRun(10, func() {
			v, _, err := codec.DecodeAPER(wire)
			if err != nil {
				panic(err)
			}
			leaf, _ := v.Value[n/2].Value.AsTAIItem()
			leaf.TAI.TAC[0] = 9
			if _, err := codec.EncodeAPER(v); err != nil {
				panic(err)
			}
		})
	}
	previous := measure(8)
	for _, n := range []int{16, 32, 64, 128} {
		next := measure(n)
		if next > 2.25*previous {
			t.Fatalf("IE/list growth %d: %.0f -> %.0f exceeds linear bound", n, previous, next)
		}
		previous = next
	}
}
func TestFragmentedNestedReplayAfterScalarEdit(t *testing.T) {
	payload := make([]byte, 65540)
	for i := range payload {
		payload[i] = byte(i*13 + 7)
	}
	table := s53.DownlinkNASTransportIEs()
	body := s53.DownlinkNASTransport{ProtocolIEs: s53.DownlinkNASTransportIEContainer{downlinkNASTransportIEFieldFreshMust(table.MMEUES1APID().New(1)), downlinkNASTransportIEFieldFreshMust(table.ENBUES1APID().New(1)), downlinkNASTransportIEFieldFreshMust(table.NASPDU().New(payload))}}
	envelope := initiatingMessageFreshMust(s65.DownlinkNASTransportProcedure().Initiating().Build(body))
	pdu := s66.S1APPDU{Choice: s00.S1APPDUChoiceInitiatingMessage, InitiatingMessage: &envelope}
	wire := sliceByteFreshMust(pdu.MarshalAPER())
	if got := fmt.Sprintf("%x", sha256.Sum256(wire)); got != "ee45378f9d91ed34a7568b07c2cbf0b5bf80c901cac7588e0ff43d08187d2c2e" {
		t.Fatal("fragmented synthetic PDU differs from independent encoder")
	}
	var value s66.S1APPDU
	if _, err := value.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxWork: 64 << 20})); err != nil {
		t.Fatal(err)
	}
	decoded, _ := value.InitiatingMessage.Value.AsDownlinkNASTransport()
	if len(decoded.ProtocolIEs[2].ReceivedForm().Location().Spans) < 2 {
		t.Fatal("field lost physical fragment spans")
	}
	if got := sliceByteFreshMust(value.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("fragmented replay differs")
	}
	id, _ := decoded.ProtocolIEs[0].Value.AsMMEUES1APID()
	*id = 2
	changed := sliceByteFreshMust(value.MarshalAPER())
	var next s66.S1APPDU
	if _, err := next.UnmarshalAPER(changed, aper.WithLimits(aper.Limits{MaxWork: 64 << 20})); err != nil {
		t.Fatal(err)
	}
	nextBody, _ := next.InitiatingMessage.Value.AsDownlinkNASTransport()
	nas, _ := nextBody.ProtocolIEs[2].Value.AsNASPDU()
	if !bytes.Equal(*nas, payload) {
		t.Fatal("scalar edit changed fragmented payload")
	}
	*id = 1
	if got := sliceByteFreshMust(value.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restored fragmented PDU did not replay")
	}
}
func TestKnownSequenceAdditionKeepsSourceSpans(t *testing.T) {
	// Independent APER encoding of SonTransfer-IEs.HOReport with candidatePCIList.
	wire, err := hex.DecodeString("8000000000000106000001020405")
	if err != nil {
		t.Fatal(err)
	}
	var value s25.HOReport
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if len(value.CandidatePCIList) != 1 || value.CandidatePCIList[0].PCI != 1 {
		t.Fatal("known addition lost typed value")
	}
	source := (*s17.BridgeCandidatePCIFieldStream(&value.CandidatePCIList[0])).ContentLocation()
	if !source.HasWireLocation || len(source.Spans) != 1 {
		t.Fatal("known addition lost original span")
	}
	value.CandidatePCIList[0].PCI = 2
	changed := sliceByteFreshMust(value.MarshalAPER())
	var next s25.HOReport
	if _, err := next.UnmarshalAPER(changed); err != nil {
		t.Fatal(err)
	}
	if next.CandidatePCIList[0].PCI != 2 {
		t.Fatal("known addition edit lost")
	}
	value.CandidatePCIList[0].PCI = 1
	if got := sliceByteFreshMust(value.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("known addition restore differs")
	}
}
func TestGenericFieldsExposeFreshCopies(t *testing.T) {
	original := tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))
	c := s42.TAIItemIEValueIEFieldTableCodec(s42.TAIItemIEs().Table())
	wire := sliceByteFreshMust(c.EncodeAPER(tAIItemIEFieldAPERValueFreshMust(c.New(original))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	copy := v.Value.WithoutReplay()
	v.Value = copy
	if got, want := sliceByteFreshMust(c.EncodeAPER(v)), sliceByteFreshMust(c.EncodeAPER(v, aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatal("generic field fresh copy differs")
	}
	if *s42.BridgeTAIItemIEFieldFieldWithoutReplay(&original) {
		t.Fatal("field copy changed original")
	}
}
func TestLargeUnchangedCompleteAllocatesOnlyResult(t *testing.T) {
	field := tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))
	fields := make(s42.TAIItemIEContainer, 128)
	for i := range fields {
		fields[i] = field
	}
	codec := s42.TAIItemIEValueIETableCodec(s42.TAIItemIEs().Table(), aper.ListBounds{Lower: 1, Upper: 256})
	wire := sliceByteFreshMust(codec.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(codec.New(fields))))
	v, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(20, func() {
		got, err := codec.EncodeAPER(v)
		if err != nil || !bytes.Equal(got, wire) {
			panic("unchanged replay differs")
		}
	})
	if allocs != 1 {
		t.Fatalf("unchanged large value allocates %.0f objects, want only its result", allocs)
	}
}
func TestSemanticEqualityIgnoresMandatorySliceStorage(t *testing.T) {
	c := s53.NASPDUCodec()
	original := *s01.BridgeNASPDUValueCodecFieldEncode(&c)
	calls := 0
	*s01.BridgeNASPDUValueCodecFieldEncode(&c) = func(v s00.NASPDU, fresh bool, p *aper.DecodeBudget) ([]byte, error) {
		calls++
		return original(v, fresh, p)
	}
	wire := sliceByteFreshMust(c.EncodeAPER(nASPDUAPERValueFreshMust(c.New([]byte{}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	v.Value = nil
	if got := sliceByteFreshMust(c.EncodeAPER(v)); calls != 0 || !bytes.Equal(got, wire) {
		t.Fatal("equal mandatory OCTET STRING storage called encoder")
	}
	// Optional containers still distinguish absent from present-but-empty.
	value := s26.CriticalityDiagnostics{}
	data := sliceByteFreshMust(value.MarshalAPER())
	var decoded s26.CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(data); err != nil {
		t.Fatal(err)
	}
	decoded.IEExtensions = s09.CriticalityDiagnosticsExtIEsExtContainer{}
	if _, err := decoded.MarshalAPER(); err == nil {
		t.Fatal("optional present empty container replayed as absent")
	}
}
func TestUnknownAdditionRestoreReplaysOriginalBitmap(t *testing.T) {
	value := s26.CriticalityDiagnostics{}
	if err := value.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s26.BridgeCriticalityDiagnosticsFieldExtCount(&value) = 3
	*s26.BridgeCriticalityDiagnosticsFieldExtPresent(&value) = append(*s26.BridgeCriticalityDiagnosticsFieldExtPresent(&value), false, false, false)
	*s26.BridgeCriticalityDiagnosticsFieldExtData(&value) = append(*s26.BridgeCriticalityDiagnosticsFieldExtData(&value), nil, nil, nil)
	wire := sliceByteFreshMust(value.MarshalAPER())
	var decoded s26.CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if err := decoded.RemoveExtension(0); err != nil {
		t.Fatal(err)
	}
	if err := decoded.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	if got := sliceByteFreshMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restoring the unknown addition lost received bitmap framing")
	}
	if fresh := sliceByteFreshMust(decoded.MarshalAPER(aper.WithoutReplay())); bytes.Equal(fresh, wire) {
		t.Fatal("fixture did not exercise a nonpreferred bitmap")
	}
}
func TestBitStringStorageOutsideValueIsIgnored(t *testing.T) {
	c := s37.TransportLayerAddressCodec()
	encoder := *s02.BridgeTransportLayerAddressValueCodecFieldEncode(&c)
	calls := 0
	*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&c) = func(v runtime.BitString, fresh bool, p *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, fresh, p)
	}
	wire := sliceByteFreshMust(c.EncodeAPER(transportLayerAddressAPERValueFreshMust(c.New(runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	v.Value.Bytes[0] |= 0x0f
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, wire) || calls != 0 {
		t.Fatalf("unused backing bits called encoder %d times", calls)
	}
	v.Value.Bytes = append(v.Value.Bytes, 0xff)
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, wire) || calls != 0 {
		t.Fatalf("unused backing octets called encoder %d times", calls)
	}
}
