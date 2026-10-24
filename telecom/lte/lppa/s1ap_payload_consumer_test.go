package lppa_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/lppa"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
)

// TS 36.413 V19.2.0 §9.3.2 defines procedure 47 (§9.3.6), whose message
// carries Routing-ID and LPPa-PDU, in that order (§9.3.3). LPPa-PDU is an
// OCTET STRING (§9.3.4), so the LPPa message remains an opaque byte boundary.
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
	ies := s1ap.UplinkNonUEAssociatedLPPaTransportIEs()
	routing, err := ies.RoutingID().New(9)
	if err != nil {
		t.Fatal(err)
	}
	carried, err := ies.LPPaPDU().New(innerWire)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := s1ap.NewUplinkNonUEAssociatedLPPaTransport(s1ap.UplinkNonUEAssociatedLPPaTransportIEContainer{routing, carried})
	if err != nil {
		t.Fatal(err)
	}
	initiating, err := s1ap.UplinkNonUEAssociatedLPPaTransportProcedure().Initiating().Build(transport)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := s1ap.NewS1APPDUInitiatingMessage(initiating)
	if err != nil {
		t.Fatal(err)
	}
	outerWire, err := outer.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var received s1ap.S1APPDU
	if _, err := received.UnmarshalAPER(outerWire); err != nil {
		t.Fatal(err)
	}
	if received.Choice != s1ap.S1APPDUChoiceInitiatingMessage || received.InitiatingMessage.ProcedureCode != 47 {
		t.Fatalf("outer=%+v", received)
	}
	receivedTransport, ok := received.InitiatingMessage.Value.AsUplinkNonUEAssociatedLPPaTransport()
	if !ok || len(receivedTransport.ProtocolIEs) != 2 || receivedTransport.ProtocolIEs[0].Id != 148 || receivedTransport.ProtocolIEs[1].Id != 147 {
		t.Fatalf("transport=%+v", receivedTransport)
	}
	carriedPDU, ok := receivedTransport.ProtocolIEs[1].Value.AsLPPaPDU()
	if !ok {
		t.Fatal("LPPa-PDU IE lost its type")
	}
	payload := *carriedPDU
	codec, err := (lppa.NewPayloadCodec[lppa.LPPAPDU]{}).Call(
		func(data []byte, limits lppa.PayloadLimits) (lppa.LPPAPDU, lppa.PayloadReport, error) {
			var value lppa.LPPAPDU
			report, err := value.UnmarshalAPER(data, aper.WithReceiverMode(), aper.WithLimits(aper.Limits{MaxInputBytes: limits.MaxInputBytes, MaxOpenTypeBytes: limits.MaxInputBytes, MaxDepth: limits.MaxDepth, MaxElements: limits.MaxElements, MaxWork: limits.MaxWork, MaxAllocatedBytes: limits.MaxAllocatedBytes, MaxReports: limits.MaxReports}))
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
			return value.MarshalAPER(aper.WithEncodeLimits(aper.Limits{MaxOutputBytes: limits.MaxOutputBytes, MaxOpenTypeBytes: limits.MaxOutputBytes, MaxDepth: limits.MaxDepth, MaxElements: limits.MaxElements, MaxWork: limits.MaxWork, MaxAllocatedBytes: limits.MaxAllocatedBytes, MaxReports: limits.MaxReports}))
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
	if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(append(bytes.Clone(payload), 0), codec, lppa.PayloadLimits{}); !errors.Is(err, aper.ErrSyntax) {
		t.Fatalf("foreign callback ignored trailing input: %v", err)
	}
	if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, lppa.PayloadLimits{MaxInputBytes: uint64(len(payload) - 1)}); err == nil {
		t.Fatal("carrier ignored input limit")
	}
	// The carrier and foreign operation have separate budgets (§6). Only scalar
	// ceilings cross the callback boundary; no runtime state is shared.
	for _, limits := range []lppa.PayloadLimits{{MaxWork: uint64(len(payload))}, {MaxDepth: 1}, {MaxAllocatedBytes: 1024}} {
		if _, _, err := (lppa.DecodePayload[lppa.LPPAPDU]{}).Call(payload, codec, limits); !errors.Is(err, aper.ErrLimit) {
			t.Fatalf("decode limits=%+v err=%v", limits, err)
		}
		if _, err := (lppa.EncodePayload[lppa.LPPAPDU]{}).Call(decoded, codec, limits); !errors.Is(err, aper.ErrLimit) {
			t.Fatalf("encode limits=%+v err=%v", limits, err)
		}
	}
	if _, err := (lppa.EncodePayload[lppa.LPPAPDU]{}).Call(decoded, codec, lppa.PayloadLimits{MaxOutputBytes: uint64(len(payload) - 1)}); !errors.Is(err, aper.ErrLimit) {
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
