package lppa

import (
	q11 "bytes"
	q9 "encoding/hex"
	bridge2 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	bridge3 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

func TestKnownProcedureDecodesItsTypedBody(t *q8.T) {
	wire, err := q9.DecodeString("000200000003000000")
	if err != nil {
		t.Fatal(err)
	}
	var pdu LPPAPDU
	if _, err := pdu.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	form := pdu.ReceivedForm()
	location := form.Location()
	if !form.Present() || !q11.Equal(form.OriginalBytes(), wire) || !location.HasWireLocation || location.Path != "LPPAPDU" || len(location.Spans) != 1 || location.Spans[0].End != uint64(len(wire))*8 {
		t.Fatalf("received form = %+v location=%+v", form, location)
	}
	original := append([]byte(nil), wire...)
	wire[0] ^= 0xff
	owned := form.OriginalBytes()
	owned[0] ^= 0xff
	if !q11.Equal(pdu.ReceivedForm().OriginalBytes(), original) {
		t.Fatal("received form retained caller storage")
	}
	if pdu.InitiatingMessage == nil {
		t.Fatal("missing initiating message")
	}
	body, ok := pdu.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
	if !ok || body == nil || len(body.ProtocolIEs) != 0 {
		t.Fatalf("typed body = %+v, ok=%v", body, ok)
	}
	bodyForm := body.ReceivedForm()
	bodyLocation := bodyForm.Location()
	if !bodyForm.Present() || !bodyLocation.HasWireLocation || len(bodyLocation.Spans) != 1 || bodyLocation.Spans[0] != (q12.BitSpan{Start: 48, End: 72}) || !q11.Equal(bodyForm.OriginalBytes(), original[6:]) {
		t.Fatalf("nested body form = %+v, location=%+v", bodyForm, bodyLocation)
	}
	replayed, err := pdu.MarshalAPER()
	if err != nil || !q11.Equal(replayed, original) {
		t.Fatalf("replay=%x err=%v, want %x", replayed, err, original)
	}
}
func TestUnknownProcedureHasOpaqueOrigin(t *q8.T) {
	message, err := NewOpaqueInitiatingMessage(250, CriticalityIgnore, 7, []byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := NewLPPAPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded LPPAPDU
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	opaque, ok := decoded.InitiatingMessage.Value.Opaque()
	if !ok {
		t.Fatal("unknown procedure not opaque")
	}
	if opaque.Origin().Reason != q12.UnknownSelector || !opaque.Origin().HasWireLocation || opaque.Origin().Location.Path != "InitiatingMessage.Value" || !q11.Equal(opaque.Bytes(), []byte{0x80}) {
		t.Fatalf("opaque=%x origin=%+v", opaque.Bytes(), opaque.Origin())
	}
	report, err := ValidateMessage(&decoded)
	if err != nil || report.Complete || len(report.Issues) != 1 || report.Issues[0].Code != UnknownProcedure {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !q11.Equal(replay, wire) {
		t.Fatalf("replay=%x err=%v", replay, err)
	}
}

// A fresh encoding must bypass preservation at both procedure and IE open
// values. The altered cache is an internal test fixture; callers cannot set it.
func TestWithoutReplayReencodesNestedKnownValues(t *q8.T) {
	for _, tc := range []struct {
		name string
		hex  string
		edit func(*q8.T, *LPPAPDU)
	}{
		{"procedure", "000200000003000000", func(t *q8.T, pdu *LPPAPDU) {
			*bridge0.BridgeInitiatingValueFieldReceived(&pdu.InitiatingMessage.Value) = q12.OriginalWire([]byte{0xff})
		}},
		{"IE", "0002000000080000010002000100", func(t *q8.T, pdu *LPPAPDU) {
			body, ok := pdu.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
			if !ok || len(body.ProtocolIEs) == 0 {
				t.Fatal("missing typed IE")
			}
			*bridge1.BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(&body.ProtocolIEs[0].Value) = q12.OriginalWire([]byte{0xff})
		}},
		{"list item", "000200000717000003000200010000030001000005000600000b000100", func(t *q8.T, pdu *LPPAPDU) {
			body, ok := pdu.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
			if !ok || len(body.ProtocolIEs) < 3 {
				t.Fatal("missing measurement quantities")
			}
			quantities, ok := body.ProtocolIEs[2].Value.AsMeasurementQuantities()
			if !ok || len(*quantities) == 0 {
				t.Fatal("missing measurement quantity item")
			}
			*bridge2.BridgeMeasurementQuantitiesItemIEValueFieldReceived(&(*quantities)[0].Value) = q12.OriginalWire([]byte{0xff})
		}},
	} {
		t.Run(tc.name, func(t *q8.T) {
			wire, err := q9.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			var pdu LPPAPDU
			if _, err := pdu.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			tc.edit(t, &pdu)
			hook := q11.Clone(wire)
			hook[len(hook)-1] ^= 0xff
			*bridge3.BridgeLPPAPDUFieldReceivedBytes(&pdu) = q12.OriginalWire(hook)
			preserved, err := pdu.MarshalAPER()
			if err != nil || q11.Equal(preserved, wire) {
				t.Fatalf("preserved = %x, err=%v", preserved, err)
			}
			fresh, err := pdu.MarshalAPER(q12.WithoutReplay())
			if err != nil || !q11.Equal(fresh, wire) {
				t.Fatalf("fresh = %x, err=%v, want %x", fresh, err, wire)
			}
		})
	}
}
