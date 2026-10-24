package lppa

import (
	q10 "bytes"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

func TestChoiceExtensionIsOwnedAndChecked(t *q8.T) {
	input := []byte{0x80, 0x11}
	pdu, err := NewLPPAPDUUnknownExtension(4, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 0
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded LPPAPDU
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if decoded.UnknownExtension == nil || decoded.UnknownExtension.Index() != 4 || !q10.Equal(decoded.UnknownExtension.Contents(), []byte{0x80, 0x11}) || decoded.UnknownExtension.Origin().Reason != q11.UnknownSelector {
		t.Fatalf("decoded unknown choice = %+v", decoded.UnknownExtension)
	}
	copyOfContents := decoded.UnknownExtension.Contents()
	copyOfContents[0] = 0
	if decoded.UnknownExtension.Contents()[0] != 0x80 {
		t.Fatal("choice extension leaked mutable storage")
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !q10.Equal(replay, wire) {
		t.Fatalf("choice extension replay=%x err=%v", replay, err)
	}
	if _, err := NewLPPAPDUUnknownExtension(^uint64(0), nil); err == nil {
		t.Fatal("impossible extension index accepted")
	}
}
func TestSequenceExtensionOwnsContentsAndSurvivesKnownEdit(t *q8.T) {
	var body ECIDMeasurementInitiationRequest
	input := []byte{0xde, 0xad}
	if err := body.SetExtension(3, input); err != nil {
		t.Fatal(err)
	}
	if origin := body.Extensions()[0].Origin(); origin.Reason != q11.CallerSupplied || origin.HasWireLocation {
		t.Fatalf("caller extension origin = %+v", origin)
	}
	input[0] = 0
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded ECIDMeasurementInitiationRequest
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	got := decoded.Extensions()
	if len(got) != 1 || got[0].Index() != 3 || !q10.Equal(got[0].Contents(), []byte{0xde, 0xad}) {
		t.Fatalf("extensions = %+v", got)
	}
	if origin := got[0].Origin(); origin.Reason != q11.UnknownSelector || !origin.HasWireLocation || origin.Location.Path != "Extensions[3]" || len(origin.Location.Spans) != 1 {
		t.Fatalf("received extension origin = %+v", origin)
	}
	copyOfContents := got[0].Contents()
	copyOfContents[0] = 0
	if decoded.Extensions()[0].Contents()[0] != 0xde {
		t.Fatal("extension accessor leaked mutable storage")
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !q10.Equal(replay, wire) {
		t.Fatalf("replay = %x, %v", replay, err)
	}
	if err := decoded.RemoveExtension(3); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Extensions()) != 0 {
		t.Fatal("extension survived removal")
	}
	without, err := decoded.MarshalAPER()
	if err != nil || q10.Equal(without, wire) {
		t.Fatalf("removed extension wire = %x, %v", without, err)
	}
}
func TestWithoutReplayChoosesShortestExtensionBitmap(t *q8.T) {
	var body ECIDMeasurementInitiationRequest
	if err := body.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	preferred, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	*bridge0.BridgeECIDMeasurementInitiationRequestFieldExtCount(&body) = 3
	*bridge0.BridgeECIDMeasurementInitiationRequestFieldExtPresent(&body) = append(*bridge0.BridgeECIDMeasurementInitiationRequestFieldExtPresent(&body), false, false, false)
	*bridge0.BridgeECIDMeasurementInitiationRequestFieldExtData(&body) = append(*bridge0.BridgeECIDMeasurementInitiationRequestFieldExtData(&body), nil, nil, nil)
	wider, err := body.MarshalAPER()
	if err != nil || q10.Equal(wider, preferred) {
		t.Fatalf("wide bitmap = %x, err=%v", wider, err)
	}
	var decoded ECIDMeasurementInitiationRequest
	if _, err := decoded.UnmarshalAPER(wider); err != nil {
		t.Fatalf("decode wider bitmap: %v", err)
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !q10.Equal(replay, wider) {
		t.Fatalf("default replay = %x, err=%v, want %x", replay, err, wider)
	}
	fresh, err := decoded.MarshalAPER(q11.WithoutReplay())
	if err != nil || !q10.Equal(fresh, preferred) {
		t.Fatalf("fresh = %x, err=%v, want %x", fresh, err, preferred)
	}
}
func TestWithoutReplayKeepsKnownExtensionInShortestBitmap(t *q8.T) {
	value := int64(1)
	body := NPRSSubframePartB{SIB1NBSubframeTDD: &value}
	preferred, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	*bridge1.BridgeNPRSSubframePartBFieldExtCount(&body) = 3
	*bridge1.BridgeNPRSSubframePartBFieldExtPresent(&body) = make([]bool, 4)
	*bridge1.BridgeNPRSSubframePartBFieldExtData(&body) = make([][]byte, 4)
	wider, err := body.MarshalAPER()
	if err != nil || q10.Equal(wider, preferred) {
		t.Fatalf("wide known-extension bitmap = %x, err=%v", wider, err)
	}
	var decoded NPRSSubframePartB
	if _, err := decoded.UnmarshalAPER(wider); err != nil {
		t.Fatal(err)
	}
	fresh, err := decoded.MarshalAPER(q11.WithoutReplay())
	if err != nil || !q10.Equal(fresh, preferred) {
		t.Fatalf("fresh known extension = %x, err=%v, want %x", fresh, err, preferred)
	}
}
