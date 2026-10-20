package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

// fuzzRoleCodec checks that a standalone decoder either rejects data or
// yields a value that replays data exactly, and whose DER decodes strictly
// to the same value. Tolerance must accept every strict success without a
// finding and replay it exactly. TS 29.002 V19.1.0 §17.1.1 form violations
// are strict refusals; structural and value-constraint errors also refuse.
// Editing a tolerantly decoded non-canonical holder must produce
// the same BER and DER as a fresh holder of the replacement value.
func fuzzRoleCodec[T, H any](t *testing.T, data []byte, mapProfile bool, first, second T,
	decode func([]byte, ...mapber.DecodeOption) (*H, error),
	encode func(*H, ...mapber.EncodeOption) ([]byte, error),
	der func(*H) ([]byte, error),
	field func(*H) *T,
) {
	decoded, err := decode(data)
	if err != nil {
		return
	}
	if replay, err := encode(decoded); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T replay = %x, %v; want %x", *field(decoded), replay, err, data)
	}
	var acceptedLog mapber.ViolationLog
	acceptedOption := mapber.WithTolerance(&acceptedLog)
	tolerant, err := decode(data, acceptedOption)
	if err != nil || len(acceptedLog.Snapshot()) != 0 {
		t.Fatalf("%T tolerant strict-success decode: %v; findings %+v", *field(decoded), err, acceptedLog.Snapshot())
	}
	if !reflect.DeepEqual(*field(tolerant), *field(decoded)) {
		t.Fatalf("%T tolerance changed the strict value", *field(decoded))
	}
	if replay, err := encode(tolerant, acceptedOption); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T tolerant replay = %x, %v; want %x", *field(decoded), replay, err, data)
	}
	canonical, err := der(decoded)
	if err != nil {
		t.Fatalf("%T DER: %v", *field(decoded), err)
	}
	again, err := decode(canonical)
	if err != nil || !reflect.DeepEqual(*field(again), *field(decoded)) {
		t.Fatalf("%T DER %x decodes to %#v, %v", *field(decoded), canonical, again, err)
	}

	// All ten role types have one-octet tags. Add a length octet to make a
	// nonminimal generic BER form (X.690 (02/2021) §8.1.3.5).
	// MAP types refuse it under TS 29.002 V19.1.0 §17.1.1;
	// SS-UserData belongs to TS 24.080 and keeps generic BER.
	var long []byte
	if canonical[1] < 0x80 {
		long = append([]byte{canonical[0], 0x81}, canonical[1:]...)
	} else {
		long = append([]byte{canonical[0], canonical[1] + 1, 0}, canonical[2:]...)
	}
	edited, err := decode(long)
	var replayOptions []mapber.EncodeOption
	if mapProfile {
		strict := checkMAPShortLengthError(t, err, 0, nil)
		var log mapber.ViolationLog
		edited, err = decode(long, mapber.WithTolerance(&log))
		if err != nil {
			t.Fatal(err)
		}
		checkMAPShortLengthLog(t, &log, strict)
		var replayLog mapber.ViolationLog
		replayOptions = []mapber.EncodeOption{mapber.WithTolerance(&replayLog)}
	} else if err != nil {
		t.Fatalf("%T long-form decode: %v", *field(decoded), err)
	}
	if replay, err := encode(edited, replayOptions...); err != nil || !bytes.Equal(replay, long) {
		t.Fatalf("%T long-form replay = %x, %v; want %x", *field(decoded), replay, err, long)
	}
	if fresh, err := encode(edited, mapber.WithoutBERReplay()); err != nil || !bytes.Equal(fresh, canonical) {
		t.Fatalf("%T long-form fresh BER = %x, %v; want %x", *field(decoded), fresh, err, canonical)
	}
	if fresh, err := der(edited); err != nil || !bytes.Equal(fresh, canonical) {
		t.Fatalf("%T long-form DER = %x, %v; want %x", *field(decoded), fresh, err, canonical)
	}
	replacement := first
	if reflect.DeepEqual(*field(edited), first) {
		replacement = second
	}
	if reflect.DeepEqual(*field(edited), replacement) {
		t.Fatal("edit must change Value")
	}
	fresh := freshRoleHolder(replacement, field)
	want, err := der(fresh)
	if err != nil {
		t.Fatalf("%T fresh DER: %v", replacement, err)
	}
	if encoded, err := encode(fresh); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T fresh BER = %x, %v; want %x", replacement, encoded, err, want)
	}
	*field(edited) = replacement
	if encoded, err := encode(edited); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T edited BER = %x, %v; want %x", replacement, encoded, err, want)
	}
	if encoded, err := der(edited); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T edited DER = %x, %v; want %x", replacement, encoded, err, want)
	}
}

// fuzzMAPExtensibleSequence checks the strict and tolerant decoders of an
// extensible SEQUENCE: whatever either accepts replays exactly, a strict
// success reports no violation under tolerance. Tag-order tolerance admission
// is checked separately by TestNotifySSArgComponentOrder.
func fuzzMAPExtensibleSequence(t *testing.T, data []byte, fresh func() mapBERValue) {
	strict := fresh()
	strictErr := strict.UnmarshalBER(data)
	if strictErr == nil {
		if replay, err := strict.MarshalBER(); err != nil || !bytes.Equal(replay, data) {
			t.Fatalf("%T strict replay = %x, %v; want %x", strict, replay, err, data)
		}
	}
	var log mapber.ViolationLog
	option := mapber.WithTolerance(&log)
	tolerant := fresh()
	if err := tolerant.UnmarshalBER(data, option); err != nil {
		if strictErr == nil {
			t.Fatalf("%T tolerant rejected a strict value: %v", tolerant, err)
		}
		return
	}
	if strictErr == nil && len(log.Snapshot()) != 0 {
		t.Fatalf("%T strict value reported %+v", tolerant, log.Snapshot())
	}
	if replay, err := tolerant.MarshalBER(option); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T tolerant replay = %x, %v; want %x", tolerant, replay, err, data)
	}
}

func FuzzMAPRoleTypeDecoders(f *testing.F) {
	for _, seed := range mapRoleDecoderSeeds() {
		f.Add(mustHexF(f, seed.wire))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoleCodec(t, data, true, gsm_map.ISDNAddressString{0x91, 0x1f}, gsm_map.ISDNAddressString{0x91, 0x2f}, gsm_map.UnmarshalBERISDNAddressString, gsm_map.MarshalBERISDNAddressString, gsm_map.MarshalDERISDNAddressString, func(v *gsm_map.BERValue[gsm_map.ISDNAddressString]) *gsm_map.ISDNAddressString { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.IMSI{0x21, 0x43, 0x65}, gsm_map.IMSI{0x65, 0x87, 0x21}, gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI, func(v *gsm_map.BERValue[gsm_map.IMSI]) *gsm_map.IMSI { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.SSCode{0x92}, gsm_map.SSCode{0x93}, gsm_map.UnmarshalBERSSCode, gsm_map.MarshalBERSSCode, gsm_map.MarshalDERSSCode, func(v *gsm_map.BERValue[gsm_map.SSCode]) *gsm_map.SSCode { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.Password("0000"), gsm_map.Password("1234"), gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword, func(v *gsm_map.BERValue[gsm_map.Password]) *gsm_map.Password { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.GuidanceInfoEnterPW, gsm_map.GuidanceInfoEnterNewPW, gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo, func(v *gsm_map.BERValue[gsm_map.GuidanceInfo]) *gsm_map.GuidanceInfo { return &v.Value })
		fuzzRoleCodec(t, data, false, gsm_map.SSUserData("A"), gsm_map.SSUserData("B"), gsm_map.UnmarshalBERSSUserData, gsm_map.MarshalBERSSUserData, gsm_map.MarshalDERSSUserData, func(v *gsm_map.BERValue[gsm_map.SSUserData]) *gsm_map.SSUserData { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.SSStatus{0x05}, gsm_map.SSStatus{0x0a}, gsm_map.UnmarshalBERSSStatus, gsm_map.MarshalBERSSStatus, gsm_map.MarshalDERSSStatus, func(v *gsm_map.BERValue[gsm_map.SSStatus]) *gsm_map.SSStatus { return &v.Value })
		fuzzRoleCodec(t, data, true, gsm_map.PWRegistrationFailureCauseUndetermined, gsm_map.PWRegistrationFailureCauseInvalidFormat, gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause, gsm_map.MarshalDERPWRegistrationFailureCause, func(v *gsm_map.BERValue[gsm_map.PWRegistrationFailureCause]) *gsm_map.PWRegistrationFailureCause {
			return &v.Value
		})
		fuzzRoleCodec(t, data, true, v21_map_ss_datatypes.SSSSStatus{0x0c}, v21_map_ss_datatypes.SSSSStatus{0x03}, v21_map_ss_datatypes.UnmarshalBERSSSSStatus, v21_map_ss_datatypes.MarshalBERSSSSStatus, v21_map_ss_datatypes.MarshalDERSSSSStatus, func(v *v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]) *v21_map_ss_datatypes.SSSSStatus {
			return &v.Value
		})
		fuzzRoleCodec(t, data, true, v21_map_er_datatypes.ERPWRegistrationFailureCauseUndetermined, v21_map_er_datatypes.ERPWRegistrationFailureCauseInvalidFormat, v21_map_er_datatypes.UnmarshalBERERPWRegistrationFailureCause, v21_map_er_datatypes.MarshalBERERPWRegistrationFailureCause, v21_map_er_datatypes.MarshalDERERPWRegistrationFailureCause, func(v *v21_map_er_datatypes.BERValue[v21_map_er_datatypes.ERPWRegistrationFailureCause]) *v21_map_er_datatypes.ERPWRegistrationFailureCause {
			return &v.Value
		})
	})
}

type mapRoleDecoderSeed struct {
	wire, constraint string
	decode           func([]byte, ...mapber.DecodeOption) error
}

// Keep every original fuzz seed and state its expectation for the matching
// decoder: short MAP lengths succeed, long MAP lengths violate TS 29.002
// V19.1.0 §17.1.1, and TS 24.080 SS-UserData keeps generic BER.
func mapRoleDecoderSeeds() []mapRoleDecoderSeed {
	var short, long []mapRoleDecoderSeed
	for _, pair := range []struct {
		short, long string
		profile     bool
		decode      func([]byte, ...mapber.DecodeOption) error
	}{
		{"0402911f", "048102911f", true, roleSeedDecoder(gsm_map.UnmarshalBERISDNAddressString)},
		{"0403214365", "048103214365", true, roleSeedDecoder(gsm_map.UnmarshalBERIMSI)},
		{"040192", "04810192", true, roleSeedDecoder(gsm_map.UnmarshalBERSSCode)},
		{"040105", "04810105", true, roleSeedDecoder(gsm_map.UnmarshalBERSSStatus)},
		{"04010c", "0481010c", true, roleSeedDecoder(v21_map_ss_datatypes.UnmarshalBERSSSSStatus)},
		{"120430303030", "12810430303030", true, roleSeedDecoder(gsm_map.UnmarshalBERPassword)},
		{"0a0100", "0a810100", true, roleSeedDecoder(gsm_map.UnmarshalBERGuidanceInfo)},
		{"160141", "16810141", false, roleSeedDecoder(gsm_map.UnmarshalBERSSUserData)},
	} {
		constraint := ""
		if pair.profile {
			constraint = "TS 29.002 §17.1.1: short-length"
		}
		short = append(short, mapRoleDecoderSeed{pair.short, "", pair.decode})
		long = append(long, mapRoleDecoderSeed{pair.long, constraint, pair.decode})
	}
	seeds := append(short, long...)
	// TS 29.002 V19.1.0 §17.7.8: Password permits digits only.
	return append(seeds, mapRoleDecoderSeed{"120420303030", "FROM permitted alphabet", roleSeedDecoder(gsm_map.UnmarshalBERPassword)})
}

func roleSeedDecoder[H any](decode func([]byte, ...mapber.DecodeOption) (*H, error)) func([]byte, ...mapber.DecodeOption) error {
	return func(data []byte, opts ...mapber.DecodeOption) error {
		_, err := decode(data, opts...)
		return err
	}
}

func TestMAPRoleTypeDecoderSeeds(t *testing.T) {
	for _, seed := range mapRoleDecoderSeeds() {
		t.Run(seed.wire, func(t *testing.T) {
			wire := mustHex(t, seed.wire)
			err := seed.decode(wire)
			var strict mapber.Violation
			switch seed.constraint {
			case "":
				if err != nil {
					t.Fatalf("compliant seed: %v", err)
				}
			case "TS 29.002 §17.1.1: short-length":
				strict = checkMAPShortLengthError(t, err, 0, nil)
			default:
				var validation *mapber.ValidationError
				if !errors.As(err, &validation) || validation.Constraint != seed.constraint {
					t.Fatalf("seed refusal = %v; want %s", err, seed.constraint)
				}
			}
			var log mapber.ViolationLog
			if err := seed.decode(wire, mapber.WithTolerance(&log)); err != nil {
				t.Fatalf("tolerant seed: %v", err)
			}
			if strict.Offset != nil {
				checkMAPShortLengthLog(t, &log, strict)
			} else if rows := log.Snapshot(); seed.constraint == "" && len(rows) != 0 || seed.constraint != "" && (len(rows) != 1 || rows[0].Constraint != seed.constraint) {
				t.Fatalf("seed findings = %+v; want %q", rows, seed.constraint)
			}
		})
	}
}

func FuzzMAPExtensionTail(f *testing.F) {
	for _, seed := range []string{
		"3003810100", "3006810100840100", "3006840100810100", "3006810100810101", "3009850101810100840100",
		"3008a306040400000000", "3005a303800100",
		"301b8000810083008401008600850087008b008800890207808a008c00",
		"3010800192a1053003840101820420303030",
	} {
		f.Add(mustHexF(f, seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzMAPExtensibleSequence(t, data, func() mapBERValue { return &gsm_map.NotifySSArg{} })
		fuzzMAPExtensibleSequence(t, data, func() mapBERValue { return &gsm_map.SingleRelativeResult{} })
		fuzzMAPExtensibleSequence(t, data, func() mapBERValue { return &gsm_map.RequestedInfo{} })
		fuzzMAPExtensibleSequence(t, data, func() mapBERValue { return &gsm_map.ExtCallBarringInfoForCSE{} })
	})
}

func mustHexF(f *testing.F, text string) []byte {
	f.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func fuzzExtensibleSequence(t *testing.T, data []byte, fresh func() berValue) {
	strict := fresh()
	strictErr := strict.UnmarshalBER(data)
	if strictErr == nil {
		if replay, err := strict.MarshalBER(); err != nil || !bytes.Equal(replay, data) {
			t.Fatalf("%T strict replay = %x, %v; want %x", strict, replay, err, data)
		}
	}
	var log ber.ViolationLog
	option := ber.WithConstraintTolerance(&log)
	tolerant := fresh()
	if err := tolerant.UnmarshalBER(data, option); err != nil {
		if strictErr == nil {
			t.Fatalf("%T tolerant rejected a strict value: %v", tolerant, err)
		}
		return
	}
	if strictErr == nil && len(log.Snapshot()) != 0 {
		t.Fatalf("%T strict value reported %+v", tolerant, log.Snapshot())
	}
	if replay, err := tolerant.MarshalBER(option); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T tolerant replay = %x, %v; want %x", tolerant, replay, err, data)
	}
}
