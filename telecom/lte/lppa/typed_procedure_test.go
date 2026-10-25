package lppa

import (
	"bytes"
	stdhex "encoding/hex"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

func TestKnownProcedureDecodesItsTypedBody(t *testing.T) {
	wire, err := stdhex.DecodeString("000200000003000000")
	if err != nil {
		t.Fatal(err)
	}
	var pdu LPPAPDU
	if _, err := pdu.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	form := pdu.ReceivedForm()
	location := form.Location()
	if !form.Present() || !bytes.Equal(form.OriginalBytes(), wire) || !location.HasWireLocation || location.Path != "LPPAPDU" || len(location.Spans) != 1 || location.Spans[0].End != uint64(len(wire))*8 {
		t.Fatalf("received form = %+v location=%+v", form, location)
	}
	original := append([]byte(nil), wire...)
	wire[0] ^= 0xff
	owned := form.OriginalBytes()
	owned[0] ^= 0xff
	if !bytes.Equal(pdu.ReceivedForm().OriginalBytes(), original) {
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
	if !bodyForm.Present() || !bodyLocation.HasWireLocation || len(bodyLocation.Spans) != 1 || bodyLocation.Spans[0] != (aper.BitSpan{Start: 48, End: 72}) || !bytes.Equal(bodyForm.OriginalBytes(), original[6:]) {
		t.Fatalf("nested body form = %+v, location=%+v", bodyForm, bodyLocation)
	}
	replayed, err := pdu.MarshalAPER()
	if err != nil || !bytes.Equal(replayed, original) {
		t.Fatalf("replay=%x err=%v, want %x", replayed, err, original)
	}
}
func TestUnknownProcedureHasOpaqueOrigin(t *testing.T) {
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
	if opaque.Origin().Reason != aper.UnknownSelector || !opaque.Origin().HasWireLocation || opaque.Origin().Location.Path != "InitiatingMessage.Value" || !bytes.Equal(opaque.Bytes(), []byte{0x80}) {
		t.Fatalf("opaque=%x origin=%+v", opaque.Bytes(), opaque.Origin())
	}
	report, err := ValidateMessage(&decoded)
	if err != nil || report.Complete || len(report.Issues) != 1 || report.Issues[0].Code != UnknownProcedure {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay=%x err=%v", replay, err)
	}
}

// A fresh encoding must bypass preservation at both procedure and IE open
// values. The altered cache is an internal test fixture; callers cannot set it.
func TestWithoutReplayReencodesNestedKnownValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
		edit func(*testing.T, *LPPAPDU)
	}{
		{"procedure", "000200000003000000", func(t *testing.T, pdu *LPPAPDU) {
			*s21.BridgeInitiatingValueFieldReceived(&pdu.InitiatingMessage.Value) = aper.OriginalWire([]byte{0xff})
		}},
		{"IE", "0002000000080000010002000100", func(t *testing.T, pdu *LPPAPDU) {
			body, ok := pdu.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
			if !ok || len(body.ProtocolIEs) == 0 {
				t.Fatal("missing typed IE")
			}
			*s21.BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(&body.ProtocolIEs[0].Value) = aper.OriginalWire([]byte{0xff})
		}},
		{"list item", "000200000717000003000200010000030001000005000600000b000100", func(t *testing.T, pdu *LPPAPDU) {
			body, ok := pdu.InitiatingMessage.Value.AsECIDMeasurementInitiationRequest()
			if !ok || len(body.ProtocolIEs) < 3 {
				t.Fatal("missing measurement quantities")
			}
			quantities, ok := body.ProtocolIEs[2].Value.AsMeasurementQuantities()
			if !ok || len(*quantities) == 0 {
				t.Fatal("missing measurement quantity item")
			}
			*s06.BridgeMeasurementQuantitiesItemIEValueFieldReceived(&(*quantities)[0].Value) = aper.OriginalWire([]byte{0xff})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := stdhex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			var pdu LPPAPDU
			if _, err := pdu.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			tc.edit(t, &pdu)
			hook := bytes.Clone(wire)
			hook[len(hook)-1] ^= 0xff
			*s23.BridgeLPPAPDUFieldReceivedBytes(&pdu) = aper.OriginalWire(hook)
			preserved, err := pdu.MarshalAPER()
			if err != nil || bytes.Equal(preserved, wire) {
				t.Fatalf("preserved = %x, err=%v", preserved, err)
			}
			fresh, err := pdu.MarshalAPER(aper.WithoutReplay())
			if err != nil || !bytes.Equal(fresh, wire) {
				t.Fatalf("fresh = %x, err=%v, want %x", fresh, err, wire)
			}
		})
	}
}
