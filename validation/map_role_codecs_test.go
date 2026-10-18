package validation

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

// The MAP packages use these types directly as an operation argument or
// result, or as an error parameter (ITU-T X.880 (07/1994) §§8.2.2, 8.2.5,
// 8.3.2): sendIMSI
// (ISDN-AddressString, IMSI), registerPassword (SS-Code, Password),
// getPassword (GuidanceInfo, Password), processUnstructuredSS-Data
// (SS-UserData), ss-ErrorStatus (SS-Status) and pw-RegistrationFailure
// (PW-RegistrationFailureCause). processUnstructuredSS-Data is defined in
// TS 24.080 V19.4.0 §4.2 (SS-Operations). SSSSStatus and
// ERPWRegistrationFailureCause are parameters from the historical
// MAP-Errors module. pycrate
// 0.7.11 decodes each vector to the same value and re-encodes it unchanged
// (go-asn1#116).
func TestMAPRoleTypeCodecs(t *testing.T) {
	checkRoleCodec(t, "ISDN-AddressString", "0402911f", "0402912f", gsm_map.ISDNAddressString{0x91, 0x1f}, gsm_map.ISDNAddressString{0x91, 0x2f},
		gsm_map.UnmarshalBERISDNAddressString, gsm_map.MarshalBERISDNAddressString, gsm_map.MarshalDERISDNAddressString, func(v *gsm_map.BERValue[gsm_map.ISDNAddressString]) *gsm_map.ISDNAddressString { return &v.Value })
	checkRoleCodec(t, "IMSI", "0403214365", "0403658721", gsm_map.IMSI{0x21, 0x43, 0x65}, gsm_map.IMSI{0x65, 0x87, 0x21},
		gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI, func(v *gsm_map.BERValue[gsm_map.IMSI]) *gsm_map.IMSI { return &v.Value })
	checkRoleCodec(t, "SS-Code", "040192", "040193", gsm_map.SSCode{0x92}, gsm_map.SSCode{0x93},
		gsm_map.UnmarshalBERSSCode, gsm_map.MarshalBERSSCode, gsm_map.MarshalDERSSCode, func(v *gsm_map.BERValue[gsm_map.SSCode]) *gsm_map.SSCode { return &v.Value })
	checkRoleCodec(t, "Password", "120430303030", "120431323334", gsm_map.Password("0000"), gsm_map.Password("1234"),
		gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword, func(v *gsm_map.BERValue[gsm_map.Password]) *gsm_map.Password { return &v.Value })
	checkRoleCodec(t, "GuidanceInfo", "0a0100", "0a0101", gsm_map.GuidanceInfoEnterPW, gsm_map.GuidanceInfoEnterNewPW,
		gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo, func(v *gsm_map.BERValue[gsm_map.GuidanceInfo]) *gsm_map.GuidanceInfo { return &v.Value })
	checkRoleCodec(t, "SS-UserData", "160141", "160142", gsm_map.SSUserData("A"), gsm_map.SSUserData("B"),
		gsm_map.UnmarshalBERSSUserData, gsm_map.MarshalBERSSUserData, gsm_map.MarshalDERSSUserData, func(v *gsm_map.BERValue[gsm_map.SSUserData]) *gsm_map.SSUserData { return &v.Value })
	checkRoleCodec(t, "SS-Status", "040105", "04010a", gsm_map.SSStatus{0x05}, gsm_map.SSStatus{0x0a},
		gsm_map.UnmarshalBERSSStatus, gsm_map.MarshalBERSSStatus, gsm_map.MarshalDERSSStatus, func(v *gsm_map.BERValue[gsm_map.SSStatus]) *gsm_map.SSStatus { return &v.Value })
	checkRoleCodec(t, "PW-RegistrationFailureCause", "0a0100", "0a0101", gsm_map.PWRegistrationFailureCauseUndetermined, gsm_map.PWRegistrationFailureCauseInvalidFormat,
		gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause,
		gsm_map.MarshalDERPWRegistrationFailureCause, func(v *gsm_map.BERValue[gsm_map.PWRegistrationFailureCause]) *gsm_map.PWRegistrationFailureCause {
			return &v.Value
		})
	checkRoleCodec(t, "SS-Status, historical MAP-Errors module", "04010c", "040103", v21_map_ss_datatypes.SSSSStatus{0x0c}, v21_map_ss_datatypes.SSSSStatus{0x03},
		v21_map_ss_datatypes.UnmarshalBERSSSSStatus, v21_map_ss_datatypes.MarshalBERSSSSStatus, v21_map_ss_datatypes.MarshalDERSSSSStatus, func(v *v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]) *v21_map_ss_datatypes.SSSSStatus {
			return &v.Value
		})
	checkRoleCodec(t, "PW-RegistrationFailureCause, historical MAP-Errors module", "0a0100", "0a0101",
		v21_map_er_datatypes.ERPWRegistrationFailureCauseUndetermined, v21_map_er_datatypes.ERPWRegistrationFailureCauseInvalidFormat, v21_map_er_datatypes.UnmarshalBERERPWRegistrationFailureCause,
		v21_map_er_datatypes.MarshalBERERPWRegistrationFailureCause, v21_map_er_datatypes.MarshalDERERPWRegistrationFailureCause, func(v *v21_map_er_datatypes.BERValue[v21_map_er_datatypes.ERPWRegistrationFailureCause]) *v21_map_er_datatypes.ERPWRegistrationFailureCause {
			return &v.Value
		})
}

// checkRoleCodec decodes wire, then checks replay, a value built in code and
// DER. A long-form length is valid BER (X.690 (02/2021) §8.1.3.5): it replays
// as received and DER writes the minimal form (§10.1). Truncated input,
// trailing octets and a wrong tag are rejected. Editing Value invalidates
// replay: both BER and DER must match a fresh canonical encoding of the edit.
func checkRoleCodec[T, H any](t *testing.T, name, text, editedText string, want, edited T,
	decode func([]byte, ...mapber.DecodeOption) (*H, error),
	encode func(*H, ...mapber.EncodeOption) ([]byte, error),
	der func(*H) ([]byte, error),
	field func(*H) *T,
) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		wire := mustHex(t, text)
		decoded, err := decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*field(decoded), want) {
			t.Fatalf("decoded %#v, want %#v", *field(decoded), want)
		}
		for _, form := range []struct {
			name string
			run  func() ([]byte, error)
		}{
			{"replay", func() ([]byte, error) { return encode(decoded) }},
			{"built", func() ([]byte, error) { return encode(freshRoleHolder(want, field)) }},
			{"DER", func() ([]byte, error) { return der(decoded) }},
		} {
			if got, err := form.run(); err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("%s = %x, %v; want %x", form.name, got, err, wire)
			}
		}

		long := append([]byte{wire[0], 0x81}, wire[1:]...)
		decoded, err = decode(long)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := encode(decoded); err != nil || !bytes.Equal(got, long) {
			t.Fatalf("long-form replay = %x, %v; want %x", got, err, long)
		}
		if got, err := der(decoded); err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("long-form DER = %x, %v; want %x", got, err, wire)
		}
		if reflect.DeepEqual(want, edited) {
			t.Fatal("edit must change Value")
		}
		fresh := freshRoleHolder(edited, field)
		canonical, err := encode(fresh)
		if err != nil || !bytes.Equal(canonical, mustHex(t, editedText)) {
			t.Fatalf("fresh edited BER = %x, %v; want %s", canonical, err, editedText)
		}
		if got, err := der(fresh); err != nil || !bytes.Equal(got, canonical) {
			t.Fatalf("fresh edited DER = %x, %v; want %x", got, err, canonical)
		}
		*field(decoded) = edited
		if got, err := encode(decoded); err != nil || !bytes.Equal(got, canonical) {
			t.Fatalf("edited long-form BER = %x, %v; want %x", got, err, canonical)
		}
		if got, err := der(decoded); err != nil || !bytes.Equal(got, canonical) {
			t.Fatalf("edited long-form DER = %x, %v; want %x", got, err, canonical)
		}

		for cut := range len(wire) {
			if _, err := decode(wire[:cut]); err == nil {
				t.Fatalf("accepted %x", wire[:cut])
			}
		}
		if _, err := decode(append(append([]byte(nil), wire...), 0)); !errors.Is(err, mapber.ErrExtraData) {
			t.Fatalf("trailing octet: %v", err)
		}
		wrong := append([]byte(nil), wire...)
		wrong[0] ^= 0x80 // UNIVERSAL to CONTEXT
		if _, err := decode(wrong); !errors.Is(err, mapber.ErrInvalidTag) {
			t.Fatalf("wrong tag: %v", err)
		}
	})
}

// The standalone functions check the constraints of the type (3GPP TS
// 29.002 V19.1.0 §§17.7.4, 17.7.7, 17.7.8): IMSI SIZE (3..8), Password
// NumericString (FROM ("0".."9")) (SIZE (4)) and the closed GuidanceInfo and
// PW-RegistrationFailureCause enumerations. pycrate 0.7.11 rejects every
// invalid value below.
func TestMAPRoleTypeConstraints(t *testing.T) {
	for _, c := range []struct {
		hex  string
		size int
	}{
		{"04022143", 2},
		{"040921436587092143f509", 9},
	} {
		wire := mustHex(t, c.hex)
		checkRoleConstraint(t, "IMSI", c.hex, gsm_map.IMSI(wire[2:]),
			mapber.Violation{Path: "IMSI", Constraint: "SIZE (3..8)", ObservedLength: &c.size},
			gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI, func(v *gsm_map.BERValue[gsm_map.IMSI]) *gsm_map.IMSI { return &v.Value })
	}
	shortSize, longSize := 3, 5
	for _, c := range []struct {
		hex, value, constraint, observed string
		length                           *int
	}{
		{"120420303030", " 000", "FROM permitted alphabet", "0x20", nil},
		{"120430303041", "000A", "FROM permitted alphabet", "0x41", nil},
		{"1203303030", "000", "SIZE (4)", "", &shortSize},
		{"12053030303030", "00000", "SIZE (4)", "", &longSize},
	} {
		checkRoleConstraint(t, "Password", c.hex, gsm_map.Password(c.value),
			mapber.Violation{Path: "Password", Constraint: c.constraint, ObservedValue: c.observed, ObservedLength: c.length},
			gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword, func(v *gsm_map.BERValue[gsm_map.Password]) *gsm_map.Password { return &v.Value })
	}
	for _, c := range []struct {
		hex, observed string
		value         int64
	}{
		{"0a0103", "3", 3},
		{"0a01ff", "-1", -1},
	} {
		checkRoleConstraint(t, "GuidanceInfo", c.hex, gsm_map.GuidanceInfo(c.value),
			mapber.Violation{Path: "GuidanceInfo", Constraint: "ENUMERATED {0, 1, 2}", ObservedValue: c.observed},
			gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo, func(v *gsm_map.BERValue[gsm_map.GuidanceInfo]) *gsm_map.GuidanceInfo { return &v.Value })
		violation := mapber.Violation{Path: "PW-RegistrationFailureCause", Constraint: "ENUMERATED {0, 1, 2}", ObservedValue: c.observed}
		checkRoleConstraint(t, "PW-RegistrationFailureCause", c.hex, gsm_map.PWRegistrationFailureCause(c.value), violation,
			gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause,
			gsm_map.MarshalDERPWRegistrationFailureCause, func(v *gsm_map.BERValue[gsm_map.PWRegistrationFailureCause]) *gsm_map.PWRegistrationFailureCause {
				return &v.Value
			})
		checkRoleConstraint(t, "PW-RegistrationFailureCause, historical MAP-Errors module", c.hex, v21_map_er_datatypes.ERPWRegistrationFailureCause(c.value), violation,
			v21_map_er_datatypes.UnmarshalBERERPWRegistrationFailureCause, v21_map_er_datatypes.MarshalBERERPWRegistrationFailureCause,
			v21_map_er_datatypes.MarshalDERERPWRegistrationFailureCause, func(v *v21_map_er_datatypes.BERValue[v21_map_er_datatypes.ERPWRegistrationFailureCause]) *v21_map_er_datatypes.ERPWRegistrationFailureCause {
				return &v.Value
			})
	}
}

// Strict BER and DER reject the invalid typed value; tolerance retains the
// value, reports the exact violation on decode and encode, and replays the wire.
func checkRoleConstraint[T, H any](t *testing.T, name, text string, want T, violation mapber.Violation,
	decode func([]byte, ...mapber.DecodeOption) (*H, error),
	encode func(*H, ...mapber.EncodeOption) ([]byte, error),
	der func(*H) ([]byte, error),
	field func(*H) *T,
) {
	t.Helper()
	t.Run(name+"/"+text, func(t *testing.T) {
		wire := mustHex(t, text)
		var constraint *mapber.ValidationError
		if _, err := decode(wire); !errors.As(err, &constraint) {
			t.Fatalf("strict decode: %v", err)
		}
		fresh := freshRoleHolder(want, field)
		if _, err := encode(fresh); !errors.As(err, &constraint) {
			t.Fatalf("strict encode: %v", err)
		}
		if _, err := der(fresh); !errors.As(err, &constraint) {
			t.Fatalf("fresh DER: %v", err)
		}
		var log mapber.ViolationLog
		option := mapber.WithTolerance(&log)
		tolerant, err := decode(wire, option)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*field(tolerant), want) {
			t.Fatalf("tolerant value = %#v, want %#v", *field(tolerant), want)
		}
		requireMAPViolations(t, &log, violation)
		if _, err := encode(tolerant); !errors.As(err, &constraint) {
			t.Fatalf("strict encode of tolerated value: %v", err)
		}
		if _, err := der(tolerant); !errors.As(err, &constraint) {
			t.Fatalf("DER of tolerated value: %v", err)
		}
		log.Reset()
		if replay, err := encode(tolerant, option); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("tolerant replay = %x, %v; want %x", replay, err, wire)
		}
		requireMAPViolations(t, &log, violation)
	})
}

// Ext-CallBarringInfoFor-CSE (3GPP TS 29.002 V19.1.0 §17.7.1) carries an optional
// Password. Earlier releases checked only its size; a strict decode now
// rejects a character outside the alphabet as well, and the tolerance option
// records it under the component path and replays it. pycrate 0.7.11
// decodes the digit form and rejects the other.
func TestPasswordAlphabetInComposite(t *testing.T) {
	valid := mustHex(t, "3010800192a1053003840101820430303030")
	var value gsm_map.ExtCallBarringInfoForCSE
	if err := value.UnmarshalBER(valid); err != nil || value.Password == nil || *value.Password != "0000" {
		t.Fatalf("valid value: %v, %+v", err, value)
	}

	invalid := mustHex(t, "3010800192a1053003840101820420303030")
	var constraint *mapber.ValidationError
	if err := new(gsm_map.ExtCallBarringInfoForCSE).UnmarshalBER(invalid); !errors.As(err, &constraint) {
		t.Fatalf("strict decode: %v", err)
	}
	var log mapber.ViolationLog
	var tolerant gsm_map.ExtCallBarringInfoForCSE
	if err := tolerant.UnmarshalBER(invalid, mapber.WithTolerance(&log)); err != nil {
		t.Fatal(err)
	}
	want := []mapber.Violation{{Path: "password", Constraint: "FROM permitted alphabet", ObservedValue: "0x20"}}
	requireMAPViolations(t, &log, want...)
	if _, err := tolerant.MarshalBER(); !errors.As(err, &constraint) {
		t.Fatalf("strict encode of the tolerated value: %v", err)
	}
	if _, err := tolerant.MarshalDER(); !errors.As(err, &constraint) {
		t.Fatalf("DER of the tolerated value: %v", err)
	}
	if got, err := tolerant.MarshalBER(mapber.WithTolerance(&log)); err != nil || !bytes.Equal(got, invalid) {
		t.Fatalf("tolerant replay = %x, %v", got, err)
	}
}

// freshRoleHolder constructs the holder belonging to the selected codec package.
func freshRoleHolder[T, H any](value T, field func(*H) *T) *H {
	holder := new(H)
	*field(holder) = value
	return holder
}
