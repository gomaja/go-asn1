package validation

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
)

// Every root component of NotifySS-Arg (3GPP TS 24.080 V19.4.0 §4.4.2) is
// OPTIONAL, so the first TLV after the known components cannot carry one of
// their tags (ITU-T X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b)). A [1]
// after [4], or a second [1], is a component out of order or repeated
// (X.690 (02/2021) §§8.9.2, 8.9.3) and not an unknown addition (go-asn1#118).
func TestNotifySSArgComponentOrder(t *testing.T) {
	for _, text := range []string{"3003810100", "3006810100840100"} {
		wire := mustHex(t, text)
		var value gsm_map.NotifySSArg
		if err := value.UnmarshalBER(wire); err != nil || len(value.ExtData_) != 0 {
			t.Fatalf("%s: %v, %d unknown TLVs", text, err, len(value.ExtData_))
		}
		replaysExactly(t, text, &value, wire)
	}

	for _, c := range []struct{ hex, tail string }{
		{"3006840100810100", "810100"}, // [4] then [1]
		{"3006810100810101", "810101"}, // [1] twice
	} {
		wire := mustHex(t, c.hex)
		if err := new(gsm_map.NotifySSArg).UnmarshalBER(wire); !errors.Is(err, ber.ErrInvalidTag) {
			t.Fatalf("%s strict: %v", c.hex, err)
		}
		var log ber.ViolationLog
		var value gsm_map.NotifySSArg
		if err := value.UnmarshalBER(wire, ber.WithConstraintTolerance(&log)); err != nil {
			t.Fatalf("%s tolerant: %v", c.hex, err)
		}
		want := []ber.ConstraintViolation{{
			Path:          "ExtData_[0]",
			Constraint:    "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)",
			ObservedValue: "[CONTEXT 1 PRIMITIVE]",
		}}
		if got := log.Snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s violations = %+v", c.hex, got)
		}
		if len(value.ExtData_) != 1 || !bytes.Equal(value.ExtData_[0], mustHex(t, c.tail)) {
			t.Fatalf("%s kept %x", c.hex, value.ExtData_)
		}
		if replay, err := value.MarshalBER(); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("%s replay = %x, %v", c.hex, replay, err)
		}
	}
}

// TS 29.002 V19.1.0 §17.7.6 adds maximumRetransmissionTime [2],
// smsGmscAddress [3] and smsGmscDiameterAddress [4] to MT-ForwardSM-Arg. The
// older SMMTForwardSMArg ends at correlationID [1]; the additions reuse
// mandatory component tags or follow its trailing OPTIONAL run, so it accepts
// them as unknown additions. pycrate 0.7.11 decodes each value with the
// current type and re-encodes it unchanged.
func TestNewerMTForwardSMArgOnOlderType(t *testing.T) {
	for _, c := range []struct {
		name, hex string
		knownIP   bool
	}{
		{"maximumRetransmissionTime", "3033800821436587092143f58407914477581000000418040b914477850100f000006201012143650005e8329bfd0682040000003c", false},
		{"smsGmscAddress", "3035800821436587092143f58407914477581000000418040b914477850100f000006201012143650005e8329bfd068306914477581000", false},
		{"smsGmscDiameterAddress", "304e800821436587092143f58407914477581000000418040b914477850100f000006201012143650005e8329bfd06a41f8010676d73632e6578616d706c652e6f7267810b6578616d706c652e6f7267", false},
		{"smsOverIP-OnlyIndicator then maximumRetransmissionTime", "3035800821436587092143f58407914477581000000418040b914477850100f000006201012143650005e8329bfd06800082040000003c", true},
	} {
		wire := mustHex(t, c.hex)
		for _, tolerant := range []bool{false, true} {
			var log ber.ViolationLog
			var options []ber.DecodeOption
			if tolerant {
				options = append(options, ber.WithConstraintTolerance(&log))
			}
			var older gsm_map.SMMTForwardSMArg
			if err := older.UnmarshalBER(wire, options...); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(log.Snapshot()) != 0 || len(older.ExtData_) != 1 || (older.SmsOverIPOnlyIndicator != nil) != c.knownIP ||
				older.SmRPDA.Imsi == nil || older.SmRPOA.ServiceCentreAddressOA == nil || len(older.SmRPUI) != 24 {
				t.Fatalf("%s: %+v, %+v", c.name, older, log.Snapshot())
			}
			replaysExactly(t, c.name, &older, wire)
		}
		var current gsm_map.MTForwardSMArg
		if err := current.UnmarshalBER(wire); err != nil || len(current.ExtData_) != 0 {
			t.Fatalf("%s current type: %v, %+v", c.name, err, current)
		}
		replaysExactly(t, c.name, &current, wire)
	}
}

// TS 29.002 V19.1.0 §17.7.1 RequestedInfo inserts
// locationInformationEPS-Supported [11] before t-adsData [8]. The older
// RequestedInfo6 does not know [11], so its first unknown TLV is [11], and
// the [8], [9] and [10] that follow it are kept with it: only the first
// unknown TLV is checked, because the unknown addition before them can be
// mandatory. pycrate 0.7.11 decodes the value with the current type and
// re-encodes it unchanged.
func TestNewerRequestedInfoOnOlderType(t *testing.T) {
	text := "301b8000810083008401008600850087008b008800890207808a008c00"
	wire := mustHex(t, text)
	var older gsm_map.RequestedInfo6
	if err := older.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	if older.MnpRequestedInfo == nil || older.TAdsData != nil || len(older.ExtData_) != 5 ||
		!bytes.Equal(older.ExtData_[0], mustHex(t, "8b00")) || !bytes.Equal(older.ExtData_[1], mustHex(t, "8800")) {
		t.Fatalf("older type = %+v", older)
	}
	replaysExactly(t, "RequestedInfo6", &older, wire)

	var current gsm_map.RequestedInfo
	if err := current.UnmarshalBER(wire); err != nil || len(current.ExtData_) != 0 || current.TAdsData == nil {
		t.Fatalf("current type: %v, %+v", err, current)
	}
	replaysExactly(t, "RequestedInfo", &current, wire)
}

// TS 24.080 V19.4.0 changes SingleRelativeResult.relativeVelocity [3] from
// an OCTET STRING to the extensible RelVelocityEstimate SEQUENCE, so its
// normal tag becomes constructed (X.690 (02/2021) §8.14.4). The old primitive
// form is rejected in both modes. A constructed form of the old string is
// kept as an unknown addition: its UNIVERSAL 4 tag is not one of
// RelVelocityEstimate's. pycrate 0.7.11, compiling the V19.4.0 velocity
// types, decodes the new and the constructed forms the same way (it drops the
// unknown addition when re-encoding) and rejects the primitive one.
func TestSingleRelativeResultVelocityForms(t *testing.T) {
	legacyPrimitive := mustHex(t, "3006830400000000")
	if err := new(gsm_map.SingleRelativeResult).UnmarshalBER(legacyPrimitive); !errors.Is(err, ber.ErrInvalidTag) {
		t.Fatalf("primitive velocity strict: %v", err)
	}
	var log ber.ViolationLog
	if err := new(gsm_map.SingleRelativeResult).UnmarshalBER(legacyPrimitive, ber.WithConstraintTolerance(&log)); !errors.Is(err, ber.ErrInvalidTag) {
		t.Fatalf("primitive velocity tolerant: %v", err)
	}

	legacyConstructed := mustHex(t, "3008a306040400000000")
	var kept gsm_map.SingleRelativeResult
	if err := kept.UnmarshalBER(legacyConstructed); err != nil {
		t.Fatal(err)
	}
	velocity := kept.RelativeVelocity
	if velocity == nil || velocity.RVelocity != nil || velocity.ATransverseVelocity != nil ||
		len(velocity.ExtData_) != 1 || !bytes.Equal(velocity.ExtData_[0], mustHex(t, "040400000000")) {
		t.Fatalf("constructed legacy velocity = %+v", velocity)
	}
	replaysExactly(t, "constructed legacy velocity", &kept, legacyConstructed)

	current := mustHex(t, "3005a303800100")
	var radial gsm_map.SingleRelativeResult
	if err := radial.UnmarshalBER(current); err != nil {
		t.Fatal(err)
	}
	if radial.RelativeVelocity == nil || radial.RelativeVelocity.RVelocity == nil || *radial.RelativeVelocity.RVelocity != 0 {
		t.Fatalf("radial velocity = %+v", radial.RelativeVelocity)
	}
	replaysExactly(t, "radial velocity", &radial, current)
}
