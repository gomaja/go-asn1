package lppa_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/lppa"
	lppaaper "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
)

// TS 36.413 V19.2.0 §§9.3.3–9.3.5: procedure 47 carries Routing-ID and
// LPPa-PDU, in that order. Its OCTET STRING remains an opaque byte boundary.
// TS 36.455 V19.0.0 §§9.3.3–9.3.4 defines the synthetic ErrorIndication.
func TestS1APPayloadCodecDecodesLPPaWithoutProtocolCoupling(t *testing.T) {
	body, err := lppa.NewErrorIndication(nil)
	if err != nil {
		t.Fatal(err)
	}
	message, err := lppa.ErrorIndicationProcedure().Initiating().Build(body, 7)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := lppa.NewLPPAPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	innerWire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	payloadBuffer := per.NewBitBuffer()
	if err := per.EncodeOctetStringAligned(payloadBuffer, innerWire, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	routingBuffer := per.NewBitBuffer()
	if err := per.EncodeConstrainedWholeNumberAligned(routingBuffer, 9, 0, 255); err != nil {
		t.Fatal(err)
	}
	transport := s1ap.UplinkNonUEAssociatedLPPaTransport{ProtocolIEs: s1ap.ProtocolIEContainer{
		{Id: s1ap.IdRoutingID, Criticality: s1ap.CriticalityReject, Value: runtime.RawValue{Bytes: routingBuffer.CompleteBytes()}},
		{Id: s1ap.IdLPPaPDU, Criticality: s1ap.CriticalityReject, Value: runtime.RawValue{Bytes: payloadBuffer.CompleteBytes()}},
	}}
	transportWire, err := transport.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	outer := s1ap.NewS1APPDUInitiatingMessage(s1ap.InitiatingMessage{ProcedureCode: s1ap.IdUplinkNonUEAssociatedLPPaTransport, Criticality: s1ap.CriticalityIgnore, Value: runtime.RawValue{Bytes: transportWire}})
	outerWire, err := outer.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var received s1ap.S1APPDU
	if err := received.UnmarshalAPER(outerWire); err != nil {
		t.Fatal(err)
	}
	if received.Choice != s1ap.S1APPDUChoiceInitiatingMessage || received.InitiatingMessage.ProcedureCode != 47 {
		t.Fatalf("outer=%+v", received)
	}
	var receivedTransport s1ap.UplinkNonUEAssociatedLPPaTransport
	if err := receivedTransport.UnmarshalAPER(received.InitiatingMessage.Value.Bytes); err != nil {
		t.Fatal(err)
	}
	if len(receivedTransport.ProtocolIEs) != 2 || receivedTransport.ProtocolIEs[1].Id != 147 {
		t.Fatalf("transport=%+v", receivedTransport)
	}
	payloadReader := per.NewBitBufferFromBytes(receivedTransport.ProtocolIEs[1].Value.Bytes)
	payload, err := per.DecodeOctetStringAligned(payloadReader, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := per.ValidateOpenTypePadding(payloadReader); err != nil {
		t.Fatal(err)
	}
	codec, err := (lppa.NewPayloadCodec[lppa.LPPAPDU]{}).Call(
		func(data []byte, limits lppa.PayloadLimits) (lppa.LPPAPDU, lppa.PayloadReport, error) {
			var value lppa.LPPAPDU
			report, err := value.UnmarshalAPER(data, lppaaper.WithReceiverMode(), lppaaper.WithLimits(lppaaper.Limits{MaxInputBytes: limits.MaxInputBytes, MaxOpenTypeBytes: limits.MaxInputBytes, MaxDepth: limits.MaxDepth, MaxElements: limits.MaxElements, MaxWork: limits.MaxWork, MaxAllocatedBytes: limits.MaxAllocatedBytes, MaxReports: limits.MaxReports}))
			if err == nil && len(report.Deviations) != 0 {
				t.Errorf("unexpected deviations: %+v", report)
			}
			mapped := lppa.PayloadReport{}
			for _, deviation := range report.Deviations {
				item := lppa.PayloadDeviation{Path: string(deviation.Location.Path), Document: deviation.Rule.Document, Clause: deviation.Rule.Clause}
				if len(deviation.Location.Spans) > 0 {
					item.ByteOffset = deviation.Location.Spans[0].Start / 8
					item.BitOffset = uint8(deviation.Location.Spans[0].Start % 8)
				}
				mapped.Deviations = append(mapped.Deviations, item)
			}
			return value, mapped, err
		},
		func(value lppa.LPPAPDU, limits lppa.PayloadLimits) ([]byte, error) {
			return value.MarshalAPER(lppaaper.WithEncodeLimits(lppaaper.Limits{MaxOutputBytes: limits.MaxOutputBytes, MaxOpenTypeBytes: limits.MaxOutputBytes, MaxDepth: limits.MaxDepth, MaxElements: limits.MaxElements, MaxWork: limits.MaxWork, MaxAllocatedBytes: limits.MaxAllocatedBytes, MaxReports: limits.MaxReports}))
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, report, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, lppa.PayloadLimits{MaxInputBytes: uint64(len(innerWire))})
	if err != nil || len(report.Deviations) != 0 || decoded.InitiatingMessage == nil || decoded.InitiatingMessage.LppatransactionID != 7 {
		t.Fatalf("inner=%+v report=%+v err=%v", decoded, report, err)
	}
	if _, ok := decoded.InitiatingMessage.Value.AsErrorIndication(); !ok {
		t.Fatal("LPPa value lost its known type")
	}
	if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(append(bytes.Clone(payload), 0), codec, lppa.PayloadLimits{}); !errors.Is(err, lppaaper.ErrSyntax) {
		t.Fatalf("foreign callback ignored trailing input: %v", err)
	}
	if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, lppa.PayloadLimits{MaxInputBytes: uint64(len(payload) - 1)}); err == nil {
		t.Fatal("carrier ignored input limit")
	}
	// The carrier and foreign operation have separate budgets (§6). Only scalar
	// ceilings cross the callback boundary; no runtime state is shared.
	for _, limits := range []lppa.PayloadLimits{{MaxWork: uint64(len(payload))}, {MaxDepth: 1}, {MaxAllocatedBytes: 1024}} {
		if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, limits); !errors.Is(err, lppaaper.ErrLimit) {
			t.Fatalf("decode limits=%+v err=%v", limits, err)
		}
		if _, err := (lppa.EncodePayload[lppa.LPPAPDU]{}).Call(decoded, codec, limits); !errors.Is(err, lppaaper.ErrLimit) {
			t.Fatalf("encode limits=%+v err=%v", limits, err)
		}
	}
	if _, err := (lppa.EncodePayload[lppa.LPPAPDU]{}).Call(decoded, codec, lppa.PayloadLimits{MaxOutputBytes: uint64(len(payload) - 1)}); !errors.Is(err, lppaaper.ErrLimit) {
		t.Fatalf("callback output ceiling: %v", err)
	}
	if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, lppa.PayloadLimits{MaxOutputBytes: 1}); err != nil {
		t.Fatalf("decode applied output ceiling: %v", err)
	}
	if !bytes.Equal(payload, innerWire) {
		t.Fatal("inspection modified carrier payload")
	}
	replay, err := received.MarshalAPER()
	if err != nil || !bytes.Equal(replay, outerWire) {
		t.Fatalf("outer replay=%x err=%v", replay, err)
	}
	decoded.InitiatingMessage.LppatransactionID = 8
	edited, err := (lppa.EncodePayload[lppa.LPPAPDU]{}).Call(decoded, codec, lppa.PayloadLimits{})
	if err != nil {
		t.Fatal(err)
	}
	editedValue, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(edited, codec, lppa.PayloadLimits{})
	if err != nil || editedValue.InitiatingMessage.LppatransactionID != 8 || bytes.Equal(edited, payload) {
		t.Fatalf("edit=%+v err=%v", editedValue, err)
	}
	replay, err = received.MarshalAPER()
	if err != nil || !bytes.Equal(replay, outerWire) {
		t.Fatal("editing inner published into outer implicitly")
	}
	t.Logf("synthetic S1AP=%x LPPa=%x", outerWire, innerWire)
}
