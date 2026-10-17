package validation

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/esim/sgp32"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_code"
)

func requireConstraint(t *testing.T, err error, want ber.ConstraintViolation) {
	t.Helper()
	var violation *ber.ConstraintError
	if !errors.As(err, &violation) || !reflect.DeepEqual(violation.ConstraintViolation, want) {
		t.Fatalf("constraint = %v, want %+v", err, want)
	}
}

func requireViolations(t *testing.T, log *ber.ViolationLog, want ...ber.ConstraintViolation) {
	t.Helper()
	got := log.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("violations = %+v, want %+v", got, want)
	}
	remaining := append([]ber.ConstraintViolation(nil), got...)
	for _, record := range want {
		// Logged diagnostics retain the original byte length, even without clipping.
		if record.ObservedValueLength == 0 {
			record.ObservedValueLength = len(record.ObservedValue)
		}
		found := false
		for i, candidate := range remaining {
			if reflect.DeepEqual(candidate, record) {
				remaining = append(remaining[:i], remaining[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("violations = %+v, want %+v", got, want)
		}
	}
}

// Password's FROM and SIZE constraints are TS 29.002 V19.1.0 §17.7.4.
// X.680 (02/2021) §41 Tables 8–10 and §51.5.4, and X.690 (02/2021)
// §8.23.5 Table 3, require octet counting for these restricted strings.
func TestPasswordOctetDiagnostics(t *testing.T) {
	for _, c := range []struct{ text, observed string }{
		{"1204c3a93030", "0xC3"},
		{"1204ff303030", "0xFF"},
	} {
		t.Run(c.observed, func(t *testing.T) {
			wire := mustHex(t, c.text)
			want := ber.ConstraintViolation{Path: "Password", Constraint: "FROM permitted alphabet", ObservedValue: c.observed}
			_, err := gsm_map.UnmarshalBERPassword(wire)
			requireConstraint(t, err, want)
			var log ber.ViolationLog
			value, err := gsm_map.UnmarshalBERPassword(wire, ber.WithConstraintTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			requireViolations(t, &log, want)
			if len(value.Value) != 4 {
				t.Fatalf("Password octet count = %d", len(value.Value))
			}
			_, err = gsm_map.MarshalBERPassword(value)
			requireConstraint(t, err, want)
			_, err = gsm_map.MarshalDERPassword(value)
			requireConstraint(t, err, want)
			log.Reset()
			if replay, err := gsm_map.MarshalBERPassword(value, ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("tolerant replay = %x, %v", replay, err)
			}
			requireViolations(t, &log, want)
		})
	}
	// Five octets containing four UTF-8 runes must record SIZE (4), len=5.
	length := 5
	var log ber.ViolationLog
	if _, err := gsm_map.UnmarshalBERPassword(mustHex(t, "1205c3a9303030"), ber.WithConstraintTolerance(&log)); err != nil {
		t.Fatal(err)
	}
	requireViolations(t, &log,
		ber.ConstraintViolation{Path: "Password", Constraint: "SIZE (4)", ObservedLength: &length},
		ber.ConstraintViolation{Path: "Password", Constraint: "FROM permitted alphabet", ObservedValue: "0xC3"})
}

// TS 24.080 V19.4.0 §4.4.2 SS-UserData and RFC 5280 Appendix A.2
// DisplayText have SIZE (1..200). X.690 (02/2021) §8.23.5 Table 3
// gives one octet per IA5String character, including NUL and DELETE.
func TestRestrictedStringOctetSize(t *testing.T) {
	wire := mustHex(t, "1681ca"+strings.Repeat("c3a9", 101))
	length := 202
	for _, c := range []struct {
		name, path string
		decode     func([]byte, ...ber.DecodeOption) (berValue, error)
	}{
		{"SGP.22 DisplayText", "ia5String", func(b []byte, opts ...ber.DecodeOption) (berValue, error) {
			v := new(sgp22.DisplayText)
			return v, v.UnmarshalBER(b, opts...)
		}},
		{"SGP.32 DisplayText", "ia5String", func(b []byte, opts ...ber.DecodeOption) (berValue, error) {
			v := new(sgp32.DisplayText)
			return v, v.UnmarshalBER(b, opts...)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := ber.ConstraintViolation{Path: c.path, Constraint: "SIZE (1..200)", ObservedLength: &length}
			_, err := c.decode(wire)
			requireConstraint(t, err, ber.ConstraintViolation{Path: c.path, Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
			var log ber.ViolationLog
			value, err := c.decode(wire, ber.WithConstraintTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			requireViolations(t, &log, want, ber.ConstraintViolation{Path: c.path, Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
			log.Reset()
			if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v", replay, err)
			}
			requireViolations(t, &log, want, ber.ConstraintViolation{Path: c.path, Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
		})
	}
}

// SS-UserData ::= IA5String (SIZE (1..200)), TS 24.080 V19.4.0 §4.4.2.
func TestSSUserDataOctetConstraints(t *testing.T) {
	length := 202
	wire := mustHex(t, "1681ca"+strings.Repeat("c3a9", 101))
	want := ber.ConstraintViolation{Path: "SS-UserData", Constraint: "SIZE (1..200)", ObservedLength: &length}
	_, err := gsm_map.UnmarshalBERSSUserData(wire)
	requireConstraint(t, err, ber.ConstraintViolation{Path: "SS-UserData", Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
	var log ber.ViolationLog
	value, err := gsm_map.UnmarshalBERSSUserData(wire, ber.WithConstraintTolerance(&log))
	if err != nil {
		t.Fatal(err)
	}
	requireViolations(t, &log, want, ber.ConstraintViolation{Path: "SS-UserData", Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
	log.Reset()
	if replay, err := gsm_map.MarshalBERSSUserData(value, ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay = %x, %v", replay, err)
	}
	requireViolations(t, &log, want, ber.ConstraintViolation{Path: "SS-UserData", Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
	fresh := &gsm_map.BERValue[gsm_map.SSUserData]{Value: gsm_map.SSUserData(strings.Repeat("é", 200))}
	_, err = gsm_map.MarshalDERSSUserData(fresh)
	requireConstraint(t, err, ber.ConstraintViolation{Path: "SS-UserData", Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
	length = 400
	log.Reset()
	if _, err := gsm_map.MarshalBERSSUserData(fresh, ber.WithConstraintTolerance(&log)); err != nil {
		t.Fatal(err)
	}
	requireViolations(t, &log, want, ber.ConstraintViolation{Path: "SS-UserData", Constraint: "IA5String character repertoire (X.680 (02/2021) §41)", ObservedValue: "0xC3"})
	for _, text := range []string{"16017f", "160100", "1681c8" + strings.Repeat("41", 200)} {
		wire := mustHex(t, text)
		value, err := gsm_map.UnmarshalBERSSUserData(wire)
		if err != nil {
			t.Fatal(err)
		}
		if replay, err := gsm_map.MarshalBERSSUserData(value); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("valid replay = %x, %v", replay, err)
		}
	}
}

// X.680 (02/2021) §41 Tables 8–10 define the four character repertoires.
// The synthetic country-name and DisplayText vectors are RFC 5280 A.1/A.2.
func TestRestrictedStringRepertoires(t *testing.T) {
	for _, c := range []struct {
		name, hex, valid, path, constraint, observed string
		fresh                                        func() berValue
	}{
		{"IA5String", "160180", "16027f00", "ia5String", "IA5String character repertoire (X.680 (02/2021) §41)", "0x80", func() berValue { return new(sgp22.DisplayText) }},
		{"VisibleString", "1a02411f", "1a03207e41", "visibleString", "VisibleString character repertoire (X.680 (02/2021) §41)", "0x1F", func() berValue { return new(sgp22.DisplayText) }},
		{"NumericString", "61051203323041", "61051203323020", "x121-dcc-code", "NumericString character repertoire (X.680 (02/2021) §41)", "0x41", func() berValue { return new(sgp22.CountryName) }},
		{"PrintableString", "610413024640", "61041302273f", "iso-3166-alpha2-code", "PrintableString character repertoire (X.680 (02/2021) §41)", "0x40", func() berValue { return new(sgp22.CountryName) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := ber.ConstraintViolation{Path: c.path, Constraint: c.constraint, ObservedValue: c.observed}
			wire := mustHex(t, c.hex)
			requireConstraint(t, c.fresh().UnmarshalBER(wire), want)
			var log ber.ViolationLog
			value := c.fresh()
			if err := value.UnmarshalBER(wire, ber.WithConstraintTolerance(&log)); err != nil {
				t.Fatal(err)
			}
			requireViolations(t, &log, want)

			_, err := value.MarshalBER()
			requireConstraint(t, err, want)
			_, err = value.MarshalDER()
			requireConstraint(t, err, want)
			log.Reset()
			if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v", replay, err)
			}
			requireViolations(t, &log, want)
			valid := c.fresh()
			good := mustHex(t, c.valid)
			if err := valid.UnmarshalBER(good); err != nil {
				t.Fatal(err)
			}
			replaysExactly(t, c.name, valid, good)
		})
	}
}

// TS 24.080 V19.4.0 §4.4.2: maxNumSLPPMsg=63, maxRelatedUE=16,
// maxAreas=250. X.680 (02/2021) §51.5 defines SIZE; the diagnostic policy
// reports each violated constraint once.
// These synthetic vectors were independently decoded with pycrate 0.7.11.
func TestNamedCollectionSingleSizeRecord(t *testing.T) {
	for _, c := range []struct {
		name, hex, path, constraint string
		length                      int
		fresh                       func() berValue
	}{
		{"rangingSLPPList", "30820144a0820140" + strings.Repeat("3003800101", 64), "rangingSLPPList", "SIZE (1..63)", 64, func() berValue { return new(gsm_map.LCSDLRSPPTransportArg) }},
		{"relatedUEInfo", "305a800100a255" + strings.Repeat("3003800101", 17), "relatedUEInfo", "SIZE (1..16)", 17, func() berValue { return new(gsm_map.LCSSLMTLRArg) }},
		{"areaList", "300b800100aa0680020640a100", "areaEventReporting.areaList", "SIZE (1..250)", 0, func() berValue { return new(gsm_map.LCSSLMTLRArg) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := mustHex(t, c.hex)
			want := ber.ConstraintViolation{Path: c.path, Constraint: c.constraint, ObservedLength: &c.length}
			requireConstraint(t, c.fresh().UnmarshalBER(wire), want)
			var log ber.ViolationLog
			value := c.fresh()
			if err := value.UnmarshalBER(wire, ber.WithConstraintTolerance(&log)); err != nil {
				t.Fatal(err)
			}
			requireViolations(t, &log, want)
			switch c.name {
			case "rangingSLPPList":
				list := value.(*gsm_map.LCSDLRSPPTransportArg).RangingSLPPList
				if list == nil || len(list.Values) != 64 {
					t.Fatalf("typed rangingSLPPList = %+v", list)
				}
				for _, entry := range list.Values {
					if !bytes.Equal(entry.SLPPMsg, []byte{1}) {
						t.Fatalf("typed sLPPMsg = %x", entry.SLPPMsg)
					}
				}
			case "relatedUEInfo":
				list := value.(*gsm_map.LCSSLMTLRArg).RelatedUEInfo
				if list == nil || len(list.Values) != 17 {
					t.Fatalf("typed relatedUEInfo = %+v", list)
				}
			case "areaList":
				area := value.(*gsm_map.LCSSLMTLRArg).AreaEventReporting
				if area == nil || area.AreaList == nil || len(area.AreaList.Values) != 0 {
					t.Fatalf("typed areaEventReporting = %+v", area)
				}
			}
			_, err := value.MarshalBER()
			requireConstraint(t, err, want)
			_, err = value.MarshalDER()
			requireConstraint(t, err, want)
			log.Reset()
			if replay, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay = %x, %v", replay, err)
			}
			requireViolations(t, &log, want)
		})
	}
}

// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b and X.690
// (02/2021) §§8.9.2–8.9.3 prohibit a first extension using a trailing
// OPTIONAL component's tag, whether that component is present or absent.
func TestNotifySSArgEncoderExtensionTags(t *testing.T) {
	for _, c := range []struct {
		tail, wire, observed string
		code                 bool
	}{
		{"810100", "3006810100810100", "[CONTEXT 1 PRIMITIVE]", true},
		{"840100", "3003840100", "[CONTEXT 4 PRIMITIVE]", false},
		{"840100", "3006810100840100", "[CONTEXT 4 PRIMITIVE]", true},
	} {
		t.Run(c.wire, func(t *testing.T) {
			value := gsm_map.NotifySSArg{ExtData_: [][]byte{mustHex(t, c.tail)}}
			if c.code {
				code := v21_map_ss_code.SSSSCode{0}
				value.SsCode = &code
			}
			want := ber.ConstraintViolation{Path: "ExtData_[0]", Constraint: "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", ObservedValue: c.observed}
			_, err := value.MarshalBER()
			requireConstraint(t, err, want)
			_, err = value.MarshalDER()
			requireConstraint(t, err, want)
			var log ber.ViolationLog
			if wire, err := value.MarshalBER(ber.WithConstraintTolerance(&log)); err != nil || !bytes.Equal(wire, mustHex(t, c.wire)) {
				t.Fatalf("tolerant encode = %x, %v", wire, err)
			}
			requireViolations(t, &log, want)
		})
	}
	// Once an unknown addition appears, later TLVs may reuse the old tags.
	wire := mustHex(t, "300a8101009f3f0100810100")
	var decoded gsm_map.NotifySSArg
	if err := decoded.UnmarshalBER(wire); err != nil {
		t.Fatal(err)
	}
	if len(decoded.ExtData_) != 2 {
		t.Fatalf("extensions = %x", decoded.ExtData_)
	}
	replaysExactly(t, "later known tag", &decoded, wire)
}

func FuzzBERReleaseConstraints(f *testing.F) {
	for _, text := range []string{
		"160180", "1a02411f", "61051203323041", "610413024640",
		"300b800100aa0680020640a100", "3006810100810100",
		"30820144a0820140" + strings.Repeat("3003800101", 64),
		"305a800100a255" + strings.Repeat("3003800101", 17),
	} {
		f.Add(mustHexF(f, text))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		for _, fresh := range []func() berValue{
			func() berValue { return new(sgp22.DisplayText) },
			func() berValue { return new(sgp32.DisplayText) },
			func() berValue { return new(sgp22.CountryName) },
			func() berValue { return new(sgp32.CountryName) },
			func() berValue { return new(gsm_map.LCSDLRSPPTransportArg) },
			func() berValue { return new(gsm_map.LCSSLMTLRArg) },
			func() berValue { return new(gsm_map.NotifySSArg) },
		} {
			fuzzExtensibleSequence(t, wire, fresh)
		}
	})
}
