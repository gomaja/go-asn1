package validation

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/esim/sgp32"
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
		requireViolations(t, &log, want...)
		if len(value.ExtData_) != 1 || !bytes.Equal(value.ExtData_[0], mustHex(t, c.tail)) {
			t.Fatalf("%s kept %x", c.hex, value.ExtData_)
		}
		if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("%s replay = %x, %v", c.hex, replay, err)
		}
	}
}

// DeviceInfo (SGP.22 V2.7 Annex H) and EimConfigurationData (SGP.32 V1.3
// Annex C, SGP32Definitions) are extensible SEQUENCEs with trailing OPTIONAL
// components. Repeating a known optional tag is not an unknown addition
// (X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b; X.690 (02/2021)
// §§8.9.2–8.9.3). Each package must reject it strictly, record the exact
// first-tail violation under tolerance, retain the TLV and replay the input.
func TestSGPFirstExtensionTailComponentOrder(t *testing.T) {
	for _, c := range []struct {
		name, valid, invalid, tail, observed string
		fresh                                func() berValue
		extensions                           func(berValue) [][]byte
	}{
		{
			"SGP.22 DeviceInfo", "3012800401020304a100820821436587092143f5",
			"301c800401020304a100820821436587092143f5820865872143098765f1", "820865872143098765f1", "[CONTEXT 2 PRIMITIVE]",
			func() berValue { return &sgp22.DeviceInfo{} },
			func(v berValue) [][]byte { return v.(*sgp22.DeviceInfo).ExtData_ },
		},
		{
			"SGP.32 EimConfigurationData", "300d800365696d8106612e74657374",
			"3015800365696d8106612e746573748106622e74657374", "8106622e74657374", "[CONTEXT 1 PRIMITIVE]",
			func() berValue { return &sgp32.EimConfigurationData{} },
			func(v berValue) [][]byte { return v.(*sgp32.EimConfigurationData).ExtData_ },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			valid := mustHex(t, c.valid)
			value := c.fresh()
			if err := value.UnmarshalBER(valid); err != nil || len(c.extensions(value)) != 0 {
				t.Fatalf("valid value: %v, extensions %x", err, c.extensions(value))
			}
			replaysExactly(t, "valid", value, valid)
			wire := mustHex(t, c.invalid)
			if err := c.fresh().UnmarshalBER(wire); !errors.Is(err, ber.ErrInvalidTag) {
				t.Fatalf("strict decode: %v", err)
			}
			var log ber.ViolationLog
			value = c.fresh()
			if err := value.UnmarshalBER(wire, ber.WithConstraintTolerance(&log)); err != nil {
				t.Fatalf("tolerant decode: %v", err)
			}
			want := []ber.ConstraintViolation{{
				Path:          "ExtData_[0]",
				Constraint:    "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)",
				ObservedValue: c.observed,
			}}
			requireViolations(t, &log, want...)
			if got := c.extensions(value); !reflect.DeepEqual(got, [][]byte{mustHex(t, c.tail)}) {
				t.Fatalf("extensions = %x, want %s", got, c.tail)
			}
			if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("tolerant replay = %x, %v; want %x", replay, err, wire)
			}
		})
	}
}

// DeviceInfo (SGP.22 V2.7 Annex H) and EimConfigurationData (SGP.32 V1.3
// Annex C) have trailing OPTIONAL components. The first unknown extension
// cannot reuse a known component tag (ITU-T X.680 (02/2021) §§25.6.1,
// 25.6.3, 52.7.3 NOTE b; X.690 (02/2021) §§8.9.2–8.9.3).
func TestSGPFirstExtensionTailEncoding(t *testing.T) {
	for _, c := range []struct {
		name, valid, colliding, noncolliding, invalid, observed string
		fresh                                                   func() berValue
		extensions                                              func(berValue) *[][]byte
	}{
		{
			name:         "SGP.22 DeviceInfo",
			valid:        "3012800401020304a100820821436587092143f5",
			colliding:    "820865872143098765f1",
			noncolliding: "8300",
			invalid:      "301c800401020304a100820821436587092143f5820865872143098765f1",
			observed:     "[CONTEXT 2 PRIMITIVE]",
			fresh:        func() berValue { return &sgp22.DeviceInfo{} },
			extensions:   func(v berValue) *[][]byte { return &v.(*sgp22.DeviceInfo).ExtData_ },
		},
		{
			name:         "SGP.32 EimConfigurationData",
			valid:        "300d800365696d8106612e74657374",
			colliding:    "8106622e74657374",
			noncolliding: "8b00",
			invalid:      "3015800365696d8106612e746573748106622e74657374",
			observed:     "[CONTEXT 1 PRIMITIVE]",
			fresh:        func() berValue { return &sgp32.EimConfigurationData{} },
			extensions:   func(v berValue) *[][]byte { return &v.(*sgp32.EimConfigurationData).ExtData_ },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			value := c.fresh()
			if err := value.UnmarshalBER(mustHex(t, c.valid)); err != nil {
				t.Fatal(err)
			}
			*c.extensions(value) = [][]byte{mustHex(t, c.colliding)}
			want := ber.ConstraintViolation{Path: "ExtData_[0]", Constraint: "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", ObservedValue: c.observed}
			_, err := value.MarshalBER()
			requireConstraint(t, err, want)
			_, err = value.MarshalDER()
			requireConstraint(t, err, want)
			var log ber.ViolationLog
			wire, err := value.MarshalBER(ber.WithConstraintTolerance(&log))
			if err != nil || !bytes.Equal(wire, mustHex(t, c.invalid)) {
				t.Fatalf("tolerant BER = %x, %v", wire, err)
			}
			requireViolations(t, &log, want)
			control := c.fresh()
			if err := control.UnmarshalBER(mustHex(t, c.valid)); err != nil {
				t.Fatal(err)
			}
			*c.extensions(control) = [][]byte{mustHex(t, c.noncolliding)}
			if _, err := control.MarshalBER(); err != nil {
				t.Fatalf("noncolliding BER: %v", err)
			}
			if _, err := control.MarshalDER(); err != nil {
				t.Fatalf("noncolliding DER: %v", err)
			}
		})
	}
}

// TS 29.002 V19.1.0 §17.7.6 MT-ForwardSM-Arg has mandatory SM-RP-DA,
// SM-RP-OA and SM-RP-UI followed by OPTIONAL components. An unknown [5]
// can reuse a mandatory CHOICE alternative's tag, and a known optional tag
// can follow that unknown addition (X.680 (02/2021) §§25.6.1, 25.6.3,
// 52.7.3 NOTE b). Historical Wireshark-only types are no longer emitted;
// the current official type exercises the same extension-tail boundary.
// All address digits use Ofcom's drama mobile range +44 7700 900000..900999:
// service centre 900000, TP-OA 900001 and SMS GMSC 900002
// (https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama).
func TestMTForwardSMArgSyntheticFutureAdditions(t *testing.T) {
	for _, c := range []struct {
		name, hex string
		knownIP   bool
	}{
		{"maximumRetransmissionTime", "3033800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd0682040000003c", false},
		{"smsGmscAddress", "3036800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd06830791447700090020", false},
		{"smsGmscDiameterAddress", "304e800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd06a41f8010676d73632e6578616d706c652e6f7267810b6578616d706c652e6f7267", false},
		{"smsOverIP-OnlyIndicator then maximumRetransmissionTime", "3035800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd06800082040000003c", true},
	} {
		wire := mustHex(t, c.hex)
		for _, tolerant := range []bool{false, true} {
			var log ber.ViolationLog
			var options []ber.DecodeOption
			if tolerant {
				options = append(options, ber.WithConstraintTolerance(&log))
			}
			var current gsm_map.MTForwardSMArg
			if err := current.UnmarshalBER(wire, options...); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if len(log.Snapshot()) != 0 || len(current.ExtData_) != 0 || (current.SmsOverIPOnlyIndicator != nil) != c.knownIP ||
				current.SmRPDA.Imsi == nil || current.SmRPOA.ServiceCentreAddressOA == nil || len(current.SmRPUI) != 24 {
				t.Fatalf("%s: %+v, %+v", c.name, current, log.Snapshot())
			}
			replaysExactly(t, c.name, &current, wire)
		}
	}
	// [5] is a mandatory CHOICE alternative, outside the trailing OPTIONAL
	// run. The following [0] remains opaque rather than becoming a typed field.
	wire := mustHex(t, "3031800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd0685008000")
	for _, tolerant := range []bool{false, true} {
		var log ber.ViolationLog
		var options []ber.DecodeOption
		if tolerant {
			options = append(options, ber.WithConstraintTolerance(&log))
		}
		var current gsm_map.MTForwardSMArg
		if err := current.UnmarshalBER(wire, options...); err != nil {
			t.Fatal(err)
		}
		if len(log.Snapshot()) != 0 || current.SmsOverIPOnlyIndicator != nil || len(current.ExtData_) != 2 ||
			!bytes.Equal(current.ExtData_[0], mustHex(t, "8500")) || !bytes.Equal(current.ExtData_[1], mustHex(t, "8000")) {
			t.Fatalf("extension tail = %+v, %+v", current, log.Snapshot())
		}
		replaysExactly(t, "MTForwardSMArg unknown then optional", &current, wire)
	}
}

// TS 29.002 V19.1.0 §17.7.1 RequestedInfo ends at localTimeZoneRequest
// [12]. A synthetic future addition [13] followed by [8], [9], [10] and
// [12] is retained as five TLVs: only the first unknown tag is checked
// (X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b). The current official
// type replaces the removed Wireshark version-13 validation target.
func TestRequestedInfoSyntheticFutureAdditions(t *testing.T) {
	text := "301b8000810083008401008600850087008d008800890207808a008c00"
	wire := mustHex(t, text)
	var current gsm_map.RequestedInfo
	if err := current.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	if current.MnpRequestedInfo == nil || current.TAdsData != nil || len(current.ExtData_) != 5 ||
		!bytes.Equal(current.ExtData_[0], mustHex(t, "8d00")) || !bytes.Equal(current.ExtData_[1], mustHex(t, "8800")) {
		t.Fatalf("current type = %+v", current)
	}
	replaysExactly(t, "RequestedInfo future addition", &current, wire)
	// The original current-version input still populates its typed additions.
	known := mustHex(t, "301b8000810083008401008600850087008b008800890207808a008c00")
	var typed gsm_map.RequestedInfo
	if err := typed.UnmarshalBER(known); err != nil || len(typed.ExtData_) != 0 || typed.TAdsData == nil {
		t.Fatalf("typed current value: %v, %+v", err, typed)
	}
	replaysExactly(t, "RequestedInfo", &typed, known)
}

// The same current MAP types must refuse a first tail tag from their
// trailing OPTIONAL run; explicit tolerance records one violation and
// preserves the exact bytes (X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3
// NOTE b; X.690 (02/2021) §§8.9.2–8.9.3).
func TestCurrentMAPFirstExtensionTail(t *testing.T) {
	for _, c := range []struct {
		name, valid, tail, invalid, control, observed string
		fresh                                         func() berValue
		extensions                                    func(berValue) *[][]byte
	}{
		{"MTForwardSMArg", "302d800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd06", "8000", "3031800821436587092143f58407914477000900000418040c9144770009001000006201012143650005e8329bfd0680008000", "8500", "[CONTEXT 0 PRIMITIVE]",
			func() berValue { return &gsm_map.MTForwardSMArg{} }, func(v berValue) *[][]byte { return &v.(*gsm_map.MTForwardSMArg).ExtData_ }},
		{"RequestedInfo", "30028800", "8800", "300488008800", "8d00", "[CONTEXT 8 PRIMITIVE]",
			func() berValue { return &gsm_map.RequestedInfo{} }, func(v berValue) *[][]byte { return &v.(*gsm_map.RequestedInfo).ExtData_ }},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := mustHex(t, c.invalid)
			if err := c.fresh().UnmarshalBER(wire); !errors.Is(err, ber.ErrInvalidTag) {
				t.Fatalf("strict decode: %v", err)
			}
			want := ber.ConstraintViolation{Path: "ExtData_[0]", Constraint: "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", ObservedValue: c.observed}
			var log ber.ViolationLog
			value := c.fresh()
			if err := value.UnmarshalBER(wire, ber.WithConstraintTolerance(&log)); err != nil {
				t.Fatal(err)
			}
			requireViolations(t, &log, want)
			if got := *c.extensions(value); len(got) != 1 || !bytes.Equal(got[0], mustHex(t, c.tail)) {
				t.Fatalf("tail = %x", got)
			}
			_, err := value.MarshalBER()
			requireConstraint(t, err, want)
			_, err = value.MarshalDER()
			requireConstraint(t, err, want)
			log = ber.ViolationLog{}
			if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v", replay, err)
			}
			requireViolations(t, &log, want)
			control := c.fresh()
			if err := control.UnmarshalBER(mustHex(t, c.valid)); err != nil {
				t.Fatal(err)
			}
			*c.extensions(control) = [][]byte{mustHex(t, c.control)}
			if _, err := control.MarshalBER(); err != nil {
				t.Fatalf("noncolliding BER: %v", err)
			}
			if _, err := control.MarshalDER(); err != nil {
				t.Fatalf("noncolliding DER: %v", err)
			}
		})
	}
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
