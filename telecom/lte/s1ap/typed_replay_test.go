// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

// X.691 (02/2021) §§11.1.4,11.2.1 require zero padding inside known alternatives.
func TestFreshEncodingReachesNestedKnownPadding(t *testing.T) {
	enb := eNBIDFreshMust(s26.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18}))
	value := s18.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: enb}
	preferred := sliceByteFreshMust(value.MarshalAPER())
	malformed := bytes.Clone(preferred)
	malformed[len(malformed)-1] |= 1
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		if _, _, err := s43.GlobalENBIDCodec().DecodeAPER(malformed, options...); err == nil {
			t.Fatal("known CHOICE padding accepted")
		}
	}
	decoded, _, err := s43.GlobalENBIDCodec().DecodeAPER(preferred)
	if err != nil {
		t.Fatal(err)
	}
	copy := decoded.Value.WithoutReplay()
	if got := sliceByteFreshMust(copy.MarshalAPER()); !bytes.Equal(got, preferred) {
		t.Fatalf("fresh=%x want=%x", got, preferred)
	}
	if got := sliceByteFreshMust(s43.GlobalENBIDCodec().EncodeAPER(decoded)); !bytes.Equal(got, preferred) {
		t.Fatal("fresh copy changed replay")
	}
}
func TestFreshEncodingTrimsSequenceFraming(t *testing.T) {
	body := s22.CriticalityDiagnostics{}
	if err := body.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	preferred := sliceByteFreshMust(body.MarshalAPER())
	*s22.BridgeCriticalityDiagnosticsFieldExtCount(&body) = 3
	*s22.BridgeCriticalityDiagnosticsFieldExtPresent(&body) = append(*s22.BridgeCriticalityDiagnosticsFieldExtPresent(&body), false, false, false)
	*s22.BridgeCriticalityDiagnosticsFieldExtData(&body) = append(*s22.BridgeCriticalityDiagnosticsFieldExtData(&body), nil, nil, nil)
	wire := sliceByteFreshMust(body.MarshalAPER())
	criticalityDiagnosticsCheckFreshCodec(t, s40.CriticalityDiagnosticsCodec(), wire, preferred)
	// A known CHOICE arm's opaque-looking bytes remain a typed value after edit.
	decoded, _, err := s40.CriticalityDiagnosticsCodec().DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	form := decoded.Value.ReceivedForm()
	original := form.OriginalBytes()
	original[0] ^= 0xff
	if got := sliceByteFreshMust(s40.CriticalityDiagnosticsCodec().EncodeAPER(decoded)); !bytes.Equal(got, wire) {
		t.Fatal("received view was writable")
	}
	extensions := decoded.Value.Extensions()
	contents := extensions[0].Contents()
	contents[0] = 0
	if !bytes.Equal(decoded.Value.Extensions()[0].Contents(), []byte{0x80}) {
		t.Fatal("extension view was writable")
	}
	for _, index := range []uint64{16383, ^uint64(0)} {
		if err := decoded.Value.SetExtension(index, []byte{0}); err == nil {
			t.Fatal("impossible addition accepted")
		}
		if err := decoded.Value.RemoveExtension(index); err == nil {
			t.Fatal("impossible removal accepted")
		}
		if got := sliceByteFreshMust(s40.CriticalityDiagnosticsCodec().EncodeAPER(decoded)); !bytes.Equal(got, wire) {
			t.Fatal("refused edit damaged replay")
		}
	}
}
func TestTypedEditAndRestoreReplay(t *testing.T) {
	cause := causeFreshMust(s26.NewCauseMisc(s00.CauseMiscUnspecified))
	body := s1SetupFailureFreshMust(s50.NewS1SetupFailure(s23.S1SetupFailureIEContainer{s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().Cause().New(cause))}))
	message := unsuccessfulOutcomeFreshMust(s53.S1SetupProcedure().Unsuccessful().Build(body))
	pdu := s1APPDUFreshMust(s53.NewS1APPDUUnsuccessfulOutcome(message))
	wire := sliceByteFreshMust(pdu.MarshalAPER())
	var decoded s53.S1APPDU
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value, _ := decoded.UnsuccessfulOutcome.Value.AsS1SetupFailure()
	selected, _ := value.ProtocolIEs[0].Value.AsCause()
	old := *selected.Misc
	*selected.Misc = s00.CauseMiscHardwareFailure
	if got := sliceByteFreshMust(decoded.MarshalAPER()); bytes.Equal(got, wire) {
		t.Fatal("typed edit replayed stale bytes")
	}
	*selected.Misc = old
	if got := sliceByteFreshMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
		t.Fatal("restored semantic value lost replay")
	}
	if _, err := decoded.UnmarshalAPER([]byte{0xff}); err == nil {
		t.Fatal("malformed input accepted")
	}
	if decoded.Choice != 0 || decoded.UnsuccessfulOutcome != nil || decoded.ReceivedForm().Present() {
		t.Fatal("failed reuse retained a previous value")
	}
}
