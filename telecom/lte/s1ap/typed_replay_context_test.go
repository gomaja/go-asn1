// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestReplayHonorsCompleteCodecContext(t *testing.T) {
	nas := s43.NASPDUCodec()
	fresh := nASPDUAPERValueFreshMust(nas.New([]byte{1, 2, 3}))
	wire := sliceByteFreshMust(nas.EncodeAPER(fresh))
	decoded, _, err := nas.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	plmn := s43.PLMNidentityCodec()
	// Preserve the foreign source context in the target's concrete holder.
	foreign := func() s01.PLMNidentityAPERValue {
		sealed := s01.PLMNidentityAPERValue{Value: decoded.Value}
		*s01.BridgePLMNidentityAPERValueFieldReceived(&sealed) = *s01.BridgeNASPDUAPERValueFieldReceived(&decoded)
		*s01.BridgePLMNidentityAPERValueFieldReplay(&sealed) = *s01.BridgeNASPDUAPERValueFieldReplay(&decoded)
		*s01.BridgePLMNidentityAPERValueFieldContext(&sealed) = *s01.BridgeNASPDUAPERValueFieldContext(&decoded)
		return sealed
	}()
	got := sliceByteFreshMust(plmn.EncodeAPER(foreign))
	want := sliceByteFreshMust(plmn.EncodeAPER(pLMNidentityAPERValueFreshMust(plmn.New([]byte{1, 2, 3}))))
	if !bytes.Equal(got, want) {
		t.Fatalf("replayed a different source codec: got %x want %x", got, want)
	}
	table := s34.TAIItemIEs().Table()
	field := tAIItemIEFieldFreshMust(s34.TAIItemIEs().TAIItem().New(s34.TAIItem{TAI: s32.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))
	a := s34.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 1})
	b := s34.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	input := sliceByteFreshMust(a.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(a.New(s34.TAIItemIEContainer{field}))))
	v, _, err := a.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	got = sliceByteFreshMust(b.EncodeAPER(v))
	want = sliceByteFreshMust(b.EncodeAPER(tAIItemIEContainerAPERValueFreshMust(b.New(v.Value))))
	if !bytes.Equal(got, want) {
		t.Fatal("replayed different numeric-formal framing")
	}
	if _, err := s34.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 2, Upper: 1}).EncodeAPER(v); err == nil {
		t.Fatal("replay bypassed invalid numeric formals")
	}
}
