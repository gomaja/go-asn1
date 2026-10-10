package validation

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
)

// GSM MAP uses these types directly as an operation argument or result, or as
// an error parameter (ITU-T X.880 (07/1994) §§8.2.2, 8.2.5, 8.3.2): sendIMSI
// (ISDN-AddressString, IMSI), registerPassword (SS-Code, Password),
// getPassword (GuidanceInfo, Password), processUnstructuredSS-Data
// (SS-UserData), ss-ErrorStatus (SS-Status) and pw-RegistrationFailure
// (PW-RegistrationFailureCause). SSStatus3 and PWRegistrationFailureCause3
// are the parameters of the package's second MAP-Errors module. pycrate
// 0.7.11 decodes each vector to the same value and re-encodes it unchanged
// (go-asn1#116).
func TestMAPRoleTypeCodecs(t *testing.T) {
	checkRoleCodec(t, "ISDN-AddressString", "040100", gsm_map.ISDNAddressString{0},
		gsm_map.UnmarshalBERISDNAddressString, gsm_map.MarshalBERISDNAddressString, gsm_map.MarshalDERISDNAddressString)
	checkRoleCodec(t, "IMSI", "0403000000", gsm_map.IMSI{0, 0, 0},
		gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI)
	checkRoleCodec(t, "SS-Code", "040100", gsm_map.SSCode{0},
		gsm_map.UnmarshalBERSSCode, gsm_map.MarshalBERSSCode, gsm_map.MarshalDERSSCode)
	checkRoleCodec(t, "Password", "120430303030", gsm_map.Password("0000"),
		gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword)
	checkRoleCodec(t, "GuidanceInfo", "0a0100", gsm_map.GuidanceInfoEnterPW,
		gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo)
	checkRoleCodec(t, "SS-UserData", "160141", gsm_map.SSUserData("A"),
		gsm_map.UnmarshalBERSSUserData, gsm_map.MarshalBERSSUserData, gsm_map.MarshalDERSSUserData)
	checkRoleCodec(t, "SS-Status", "040100", gsm_map.SSStatus{0},
		gsm_map.UnmarshalBERSSStatus, gsm_map.MarshalBERSSStatus, gsm_map.MarshalDERSSStatus)
	checkRoleCodec(t, "PW-RegistrationFailureCause", "0a0100", gsm_map.PWRegistrationFailureCauseUndetermined,
		gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause,
		gsm_map.MarshalDERPWRegistrationFailureCause)
	checkRoleCodec(t, "SS-Status, second MAP-Errors module", "040100", gsm_map.SSStatus3{0},
		gsm_map.UnmarshalBERSSStatus3, gsm_map.MarshalBERSSStatus3, gsm_map.MarshalDERSSStatus3)
	checkRoleCodec(t, "PW-RegistrationFailureCause, second MAP-Errors module", "0a0100",
		gsm_map.PWRegistrationFailureCause3Undetermined, gsm_map.UnmarshalBERPWRegistrationFailureCause3,
		gsm_map.MarshalBERPWRegistrationFailureCause3, gsm_map.MarshalDERPWRegistrationFailureCause3)
}

// checkRoleCodec decodes wire, then checks replay, a value built in code and
// DER. A long-form length is valid BER (X.690 (02/2021) §8.1.3.5): it replays
// as received and DER writes the minimal form (§10.1). Truncated input,
// trailing octets and a wrong tag are rejected.
func checkRoleCodec[T any](t *testing.T, name, text string, want T,
	decode func([]byte, ...ber.DecodeOption) (*gsm_map.BERValue[T], error),
	encode func(*gsm_map.BERValue[T], ...ber.EncodeOption) ([]byte, error),
	der func(*gsm_map.BERValue[T]) ([]byte, error),
) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		wire := mustHex(t, text)
		decoded, err := decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.Value, want) {
			t.Fatalf("decoded %#v, want %#v", decoded.Value, want)
		}
		for _, form := range []struct {
			name string
			run  func() ([]byte, error)
		}{
			{"replay", func() ([]byte, error) { return encode(decoded) }},
			{"built", func() ([]byte, error) { return encode(&gsm_map.BERValue[T]{Value: want}) }},
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

		for cut := range len(wire) {
			if _, err := decode(wire[:cut]); err == nil {
				t.Fatalf("accepted %x", wire[:cut])
			}
		}
		if _, err := decode(append(append([]byte(nil), wire...), 0)); !errors.Is(err, ber.ErrExtraData) {
			t.Fatalf("trailing octet: %v", err)
		}
		wrong := append([]byte(nil), wire...)
		wrong[0] ^= 0x80 // UNIVERSAL to CONTEXT
		if _, err := decode(wrong); !errors.Is(err, ber.ErrInvalidTag) {
			t.Fatalf("wrong tag: %v", err)
		}
	})
}

// The standalone functions check the constraints of the type (3GPP TS
// 29.002 §§17.7.4, 17.7.7, 17.7.8): IMSI SIZE (3..8), Password
// NumericString (FROM ("0".."9")) (SIZE (4)) and the closed GuidanceInfo and
// PW-RegistrationFailureCause enumerations. pycrate 0.7.11 rejects every
// invalid value below.
func TestMAPRoleTypeConstraints(t *testing.T) {
	for _, text := range []string{"04020000", "0409000000000000000000"} {
		wire := mustHex(t, text)
		var constraint *ber.ConstraintError
		if _, err := gsm_map.UnmarshalBERIMSI(wire); !errors.As(err, &constraint) {
			t.Fatalf("IMSI %s: %v", text, err)
		}
		value := &gsm_map.BERValue[gsm_map.IMSI]{Value: wire[2:]}
		if _, err := gsm_map.MarshalBERIMSI(value); !errors.As(err, &constraint) {
			t.Fatalf("IMSI %s encode: %v", text, err)
		}
		if _, err := gsm_map.MarshalDERIMSI(value); !errors.As(err, &constraint) {
			t.Fatalf("IMSI %s DER: %v", text, err)
		}
		var log ber.ViolationLog
		tolerant, err := gsm_map.UnmarshalBERIMSI(wire, ber.WithConstraintTolerance(&log))
		if err != nil || len(log.Snapshot()) != 1 || log.Snapshot()[0].Constraint != "SIZE (3..8)" {
			t.Fatalf("IMSI %s tolerant: %v, %+v", text, err, log.Snapshot())
		}
		log.Reset()
		if got, err := gsm_map.MarshalBERIMSI(tolerant, ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("IMSI %s tolerant replay = %x, %v", text, got, err)
		}
	}

	for _, text := range []string{"120420303030", "120430303041", "1203303030", "12053030303030"} {
		wire := mustHex(t, text)
		var constraint *ber.ConstraintError
		if _, err := gsm_map.UnmarshalBERPassword(wire); !errors.As(err, &constraint) {
			t.Fatalf("Password %s: %v", text, err)
		}
		if _, err := gsm_map.MarshalBERPassword(&gsm_map.BERValue[gsm_map.Password]{Value: string(wire[2:])}); !errors.As(err, &constraint) {
			t.Fatalf("Password %s encode: %v", text, err)
		}
	}
	var log ber.ViolationLog
	password, err := gsm_map.UnmarshalBERPassword(mustHex(t, "120420303030"), ber.WithConstraintTolerance(&log))
	if err != nil {
		t.Fatal(err)
	}
	want := []ber.ConstraintViolation{{Path: "Password", Constraint: "FROM permitted alphabet", ObservedValue: "' '"}}
	if got := log.Snapshot(); !reflect.DeepEqual(got, want) || password.Value != " 000" {
		t.Fatalf("tolerant Password = %q, %+v", password.Value, got)
	}

	for _, text := range []string{"0a0103", "0a01ff"} {
		if _, err := gsm_map.UnmarshalBERGuidanceInfo(mustHex(t, text)); err == nil {
			t.Fatalf("GuidanceInfo %s accepted", text)
		}
		if _, err := gsm_map.UnmarshalBERPWRegistrationFailureCause(mustHex(t, text)); err == nil {
			t.Fatalf("PW-RegistrationFailureCause %s accepted", text)
		}
	}
	if _, err := gsm_map.MarshalBERGuidanceInfo(&gsm_map.BERValue[gsm_map.GuidanceInfo]{Value: 3}); err == nil {
		t.Fatal("GuidanceInfo 3 encoded")
	}
}

// Ext-CallBarringInfoFor-CSE (3GPP TS 29.002 §17.7.1) carries an optional
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
	var constraint *ber.ConstraintError
	if err := new(gsm_map.ExtCallBarringInfoForCSE).UnmarshalBER(invalid); !errors.As(err, &constraint) {
		t.Fatalf("strict decode: %v", err)
	}
	var log ber.ViolationLog
	var tolerant gsm_map.ExtCallBarringInfoForCSE
	if err := tolerant.UnmarshalBER(invalid, ber.WithConstraintTolerance(&log)); err != nil {
		t.Fatal(err)
	}
	want := []ber.ConstraintViolation{{Path: "password", Constraint: "FROM permitted alphabet", ObservedValue: "' '"}}
	if got := log.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("violations = %+v, want %+v", got, want)
	}
	if _, err := tolerant.MarshalBER(); !errors.As(err, &constraint) {
		t.Fatalf("strict encode of the tolerated value: %v", err)
	}
	if got, err := tolerant.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(got, invalid) {
		t.Fatalf("tolerant replay = %x, %v", got, err)
	}
}
