// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func TestBoundTemplateCodecsKeepTablesAndNumericBounds(t *testing.T) {
	for _, check := range []func() error{
		func() error {
			_, err := (s51.ErrorIndicationInitiatingBinding{}).Codec().New(s28.ErrorIndication{})
			return err
		},
		func() error {
			_, err := (s50.ResetAcknowledgeSuccessfulBinding{}).Codec().New(s44.ResetAcknowledge{})
			return err
		},
		func() error {
			_, err := (s36.S1SetupFailureUnsuccessfulBinding{}).Codec().New(s26.S1SetupFailure{})
			return err
		},
	} {
		if err := check(); err == nil {
			t.Fatal("zero binding codec accepted")
		}
	}

	if _, err := (s51.ErrorIndicationInitiatingBinding{}).Build(s28.ErrorIndication{}); err == nil {
		t.Fatal("zero initiating binding accepted")
	}
	if _, err := (s50.ResetAcknowledgeSuccessfulBinding{}).Build(s44.ResetAcknowledge{}); err == nil {
		t.Fatal("zero successful binding accepted")
	}
	if _, err := (s36.S1SetupFailureUnsuccessfulBinding{}).Build(s26.S1SetupFailure{}); err == nil {
		t.Fatal("zero unsuccessful binding accepted")
	}

	field := tAIItemIEFieldFreshMust(s33.TAIItemIEs().TAIItem().New(s33.TAIItem{TAI: s31.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))
	table := s33.TAIItemIEs().Table()
	codec := s33.TAIItemIEValueERABIEContainerListCodec(table)
	value := tAIItemIEValueERABIEContainerListAPERValueFreshMust(codec.New(s33.TAIItemIEValueERABIEContainerList{field}))
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
	tooMany := make(s33.TAIItemIEValueERABIEContainerList, 257)
	for i := range tooMany {
		tooMany[i] = field
	}
	if _, err := codec.New(tooMany); err == nil {
		t.Fatal("lost source upper bound")
	}
	one := s33.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 1})
	if _, err := one.New(s33.TAIItemIEContainer{field, field}); err == nil {
		t.Fatal("lost numeric formal upper bound")
	}
	if _, _, err := s33.TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 2, Upper: 1}).DecodeAPER(wire); err == nil {
		t.Fatal("invalid bounds accepted")
	}
	if _, err := s33.TAIItemIEValueIETableCodec(s00.TAIItemIEValueIETable{}, aper.ListBounds{}).New(nil); err == nil {
		t.Fatal("unbound table accepted")
	}
	if _, err := s33.TAIItemIEValueProtocolIEContainerListCodec(s00.TAIItemIEValueIETable{}, aper.ListBounds{}).New(nil); err == nil {
		t.Fatal("unbound forwarding table accepted")
	}
	single := s33.TAIItemIEValueIEFieldTableCodec(table)
	owned := tAIItemIEFieldAPERValueFreshMust(single.New(field))
	singleWire := sliceByteFreshMust(single.EncodeAPER(owned))
	if _, _, err := single.DecodeAPER(append(singleWire, 0)); err == nil {
		t.Fatal("field codec accepted trailing octet")
	}
	extension := criticalityDiagnosticsExtIEsExtFieldFreshMust(s07.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0x80}))
	extCodec := s13.CriticalityDiagnosticsExtIEsValueExtensionTableCodec(s07.CriticalityDiagnosticsExtIEs().Table(), aper.ListBounds{Lower: 1, Upper: 65535})
	extOwned := criticalityDiagnosticsExtIEsExtContainerAPERValueFreshMust(extCodec.New(s07.CriticalityDiagnosticsExtIEsExtContainer{extension}))
	if _, _, err := extCodec.DecodeAPER(sliceByteFreshMust(extCodec.EncodeAPER(extOwned))); err != nil {
		t.Fatal(err)
	}
	id := privateIEIDFreshMust(s25.NewPrivateIEIDLocal(1))
	private := privateMessageIEsValuePrivateIEFieldFreshMust(s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	privateCodec := s26.PrivateMessageIEsValuePrivateTableCodec(s25.PrivateMessageIEs().Table(), aper.ListBounds{Lower: 1, Upper: 65535})
	privateOwned := privateMessageIEsValuePrivateIEContainerAPERValueFreshMust(privateCodec.New(s25.PrivateMessageIEsValuePrivateIEContainer{private}))
	if _, _, err := privateCodec.DecodeAPER(sliceByteFreshMust(privateCodec.EncodeAPER(privateOwned))); err != nil {
		t.Fatal(err)
	}
}
