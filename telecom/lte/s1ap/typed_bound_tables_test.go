// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestBoundTemplateCodecsKeepTablesAndNumericBounds(t *testing.T) {
	for _, check := range []func() error{
		func() error {
			_, err := (s65.ErrorIndicationInitiatingBinding{}).Codec().New(s36.ErrorIndication{})
			return err
		},
		func() error {
			_, err := (s64.ResetAcknowledgeSuccessfulBinding{}).Codec().New(s55.ResetAcknowledge{})
			return err
		},
		func() error {
			_, err := (s46.S1SetupFailureUnsuccessfulBinding{}).Codec().New(s31.S1SetupFailure{})
			return err
		},
	} {
		if err := check(); err == nil {
			t.Fatal("zero binding codec accepted")
		}
	}

	if _, err := (s65.ErrorIndicationInitiatingBinding{}).Build(s36.ErrorIndication{}); err == nil {
		t.Fatal("zero initiating binding accepted")
	}
	if _, err := (s64.ResetAcknowledgeSuccessfulBinding{}).Build(s55.ResetAcknowledge{}); err == nil {
		t.Fatal("zero successful binding accepted")
	}
	if _, err := (s46.S1SetupFailureUnsuccessfulBinding{}).Build(s31.S1SetupFailure{}); err == nil {
		t.Fatal("zero unsuccessful binding accepted")
	}

	field := tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))
	table := s42.TAIItemIEs().Table()
	codec := s42.TAIItemIEValueERABIEContainerListCodec(table)
	value := tAIItemIEValueERABIEContainerListAPERValueFreshMust(codec.New(s42.TAIItemIEValueERABIEContainerList{field}))
	wire := sliceByteFreshMust(codec.EncodeAPER(value))
	got, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if replay := sliceByteFreshMust(codec.EncodeAPER(got)); !bytes.Equal(replay, wire) {
		t.Fatal("bound replay differs")
	}
	if _, err := codec.New(nil); err == nil {
		t.Fatal("lost source lower bound")
	}
	tooMany := make(s42.TAIItemIEValueERABIEContainerList, 257)
	for i := range tooMany {
		tooMany[i] = field
	}
	if _, err := codec.New(tooMany); err == nil {
		t.Fatal("lost source upper bound")
	}
	one := s42.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 1})
	if _, err := one.New(s42.TAIItemIEContainer{field, field}); err == nil {
		t.Fatal("lost numeric formal upper bound")
	}
	if _, _, err := s42.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 2, Upper: 1}).DecodeAPER(wire); err == nil {
		t.Fatal("invalid bounds accepted")
	}
	if _, err := s42.TAIItemIEValueIETableCodec(s00.TAIItemIEValueIETable{}, aper.ListBounds{}).New(nil); err == nil {
		t.Fatal("unbound table accepted")
	}
	if _, err := s42.TAIItemIEValueProtocolIEContainerListCodec(s00.TAIItemIEValueIETable{}, aper.ListBounds{}).New(nil); err == nil {
		t.Fatal("unbound forwarding table accepted")
	}
	single := s42.TAIItemIEValueIEFieldTableCodec(table)
	owned := tAIItemIEFieldAPERValueFreshMust(single.New(field))
	singleWire := sliceByteFreshMust(single.EncodeAPER(owned))
	if _, _, err := single.DecodeAPER(append(singleWire, 0)); err == nil {
		t.Fatal("field codec accepted trailing octet")
	}
	extension := criticalityDiagnosticsExtIEsExtFieldFreshMust(s09.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0x80}))
	extCodec := s15.CriticalityDiagnosticsExtIEsValueExtensionTableCodec(s09.CriticalityDiagnosticsExtIEs().Table(), aper.ListBounds{Lower: 1, Upper: 65535})
	extOwned := criticalityDiagnosticsExtIEsExtContainerAPERValueFreshMust(extCodec.New(s09.CriticalityDiagnosticsExtIEsExtContainer{extension}))
	if _, _, err := extCodec.DecodeAPER(sliceByteFreshMust(extCodec.EncodeAPER(extOwned))); err != nil {
		t.Fatal(err)
	}
	id := privateIEIDFreshMust(s30.NewPrivateIEIDLocal(1))
	private := privateMessageIEsValuePrivateIEFieldFreshMust(s29.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	privateCodec := s30.PrivateMessageIEsValuePrivateTableCodec(s29.PrivateMessageIEs().Table(), aper.ListBounds{Lower: 1, Upper: 65535})
	privateOwned := privateMessageIEsValuePrivateIEContainerAPERValueFreshMust(privateCodec.New(s29.PrivateMessageIEsValuePrivateIEContainer{private}))
	if _, _, err := privateCodec.DecodeAPER(sliceByteFreshMust(privateCodec.EncodeAPER(privateOwned))); err != nil {
		t.Fatal(err)
	}
}
