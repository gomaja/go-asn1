// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestTypedReplayFreshAndPayloadOwnership(t *testing.T) {
	cd := s06.CriticalityDiagnostics{}
	if err := cd.SetExtension(2, []byte{0}); err != nil {
		t.Fatal(err)
	}
	*s06.X2apInternalCriticalityDiagnosticsFieldExtCount(&cd) = 7
	field := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().CriticalityDiagnostics().New(cd))
	body := errorIndicationapiMust(s19.NewErrorIndication(s11.ErrorIndicationIEContainer{field}))
	wire := listByteapiMust(body.MarshalAPER())
	var received s19.ErrorIndication
	if _, err := received.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	snapshot := received.ReceivedForm().OriginalBytes()
	snapshot[0] ^= 255
	if !bytes.Equal(listByteapiMust(received.MarshalAPER()), wire) {
		t.Fatal("received form exposed mutable replay state")
	}
	fresh := listByteapiMust(received.MarshalAPER(aper.WithoutReplay()))
	if bytes.Equal(fresh, wire) {
		t.Fatal("fresh option did not reach nested IE sequence")
	}
	if !bytes.Equal(listByteapiMust(received.MarshalAPER()), wire) {
		t.Fatal("fresh encode mutated replay")
	}
	known, ok := s11.ErrorIndicationIEs().CriticalityDiagnostics().Get(&received.ProtocolIEs[0])
	if !ok || known == nil {
		t.Fatal("known IE lost its type")
	}
	codec := listBytePayloadCodecapiMust(ListByteNewPayloadCodec(func(data []byte, _ s00.PayloadLimits) ([]byte, s00.PayloadReport, error) {
		data[0]++
		return data, s00.PayloadReport{}, nil
	}, func(value []byte, _ s00.PayloadLimits) ([]byte, error) { return value, nil }))
	input := []byte{1}
	value, _, err := ListByteDecodePayload(input, codec, s00.PayloadLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if input[0] != 1 || value[0] != 2 {
		t.Fatal("payload decode did not own its bytes")
	}
	output := listByteapiMust(ListByteEncodePayload(value, codec, s00.PayloadLimits{}))
	output[0]++
	if value[0] != 2 {
		t.Fatal("payload encode returned mutable callback buffer")
	}
	if _, err := ListByteNewPayloadCodec(nil, nil); err == nil {
		t.Fatal("nil payload binding accepted")
	}
}
