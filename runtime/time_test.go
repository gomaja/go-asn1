package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

type timeExample struct {
	utc     bool
	in      string
	der     string // "" when the value has no DER form
	instant string // Time() as RFC 3339; "" when Time() fails
	zone    TimeZoneKind
	offset  int
	unit    TimeUnit
	digits  int
}

// Expected values are worked by hand from X.680 (02/2021) §§46.3, 47.3 and
// X.690 (02/2021) §§11.7, 11.8, not from the implementation.
var timeExamples = []timeExample{
	// go-asn1#86 UTCTime inputs
	{true, "2601011200Z", "260101120000Z", "2026-01-01T12:00:00Z", TimeZoneUTC, 0, TimeUnitMinute, 0},
	{true, "260101120000+0100", "260101110000Z", "2026-01-01T12:00:00+01:00", TimeZoneOffset, 60, TimeUnitSecond, 0},
	{true, "2601011200+0100", "260101110000Z", "2026-01-01T12:00:00+01:00", TimeZoneOffset, 60, TimeUnitMinute, 0},
	// X.680 §47.3 EXAMPLE 1 and 2
	{true, "8201021200Z", "820102120000Z", "1982-01-02T12:00:00Z", TimeZoneUTC, 0, TimeUnitMinute, 0},
	{true, "8201020700-0500", "820102120000Z", "1982-01-02T07:00:00-05:00", TimeZoneOffset, -300, TimeUnitMinute, 0},
	{true, "0101020700-0500", "010102120000Z", "2001-01-02T07:00:00-05:00", TimeZoneOffset, -300, TimeUnitMinute, 0},
	// UTCTime whose UTC equivalent leaves the 1950-2049 window
	{true, "491231230000-0100", "", "2049-12-31T23:00:00-01:00", TimeZoneOffset, -60, TimeUnitSecond, 0},
	{true, "500101003000+0100", "", "1950-01-01T00:30:00+01:00", TimeZoneOffset, 60, TimeUnitSecond, 0},
	// -0000 is accepted (decision D5) and is distinct from Z
	{true, "260101120000-0000", "260101120000Z", "2026-01-01T12:00:00Z", TimeZoneOffset, 0, TimeUnitSecond, 0},
	// go-asn1#86 GeneralizedTime inputs
	{false, "20260101120000Z", "20260101120000Z", "2026-01-01T12:00:00Z", TimeZoneUTC, 0, TimeUnitSecond, 0},
	{false, "202601011200Z", "20260101120000Z", "2026-01-01T12:00:00Z", TimeZoneUTC, 0, TimeUnitMinute, 0},
	{false, "2026010112Z", "20260101120000Z", "2026-01-01T12:00:00Z", TimeZoneUTC, 0, TimeUnitHour, 0},
	{false, "2026010112,5Z", "20260101123000Z", "2026-01-01T12:30:00Z", TimeZoneUTC, 0, TimeUnitHour, 1},
	{false, "202601011230.5Z", "20260101123030Z", "2026-01-01T12:30:30Z", TimeZoneUTC, 0, TimeUnitMinute, 1},
	{false, "20260101120000+01", "20260101110000Z", "2026-01-01T12:00:00+01:00", TimeZoneOffset, 60, TimeUnitSecond, 0},
	{false, "20260101120000.25", "", "", TimeZoneLocal, 0, TimeUnitSecond, 2},
	// X.680 §46.3 EXAMPLES a)–e)
	{false, "19851106210627.3", "", "", TimeZoneLocal, 0, TimeUnitSecond, 1},
	{false, "19851106210627.3Z", "19851106210627.3Z", "1985-11-06T21:06:27.3Z", TimeZoneUTC, 0, TimeUnitSecond, 1},
	{false, "19851106210627.3-0500", "19851107020627.3Z", "1985-11-06T21:06:27.3-05:00", TimeZoneOffset, -300, TimeUnitSecond, 1},
	{false, "198511062106.456", "", "", TimeZoneLocal, 0, TimeUnitMinute, 3},
	{false, "1985110621.14159", "", "", TimeZoneLocal, 0, TimeUnitHour, 5},
	{false, "1985110621.14159Z", "19851106210829.724Z", "1985-11-06T21:08:29.724Z", TimeZoneUTC, 0, TimeUnitHour, 5},
	// X.690 §11.7 examples of invalid DER (valid BER), and its valid ones
	{false, "19920622123421.0Z", "19920622123421Z", "1992-06-22T12:34:21Z", TimeZoneUTC, 0, TimeUnitSecond, 1},
	{false, "19920722132100.30Z", "19920722132100.3Z", "1992-07-22T13:21:00.3Z", TimeZoneUTC, 0, TimeUnitSecond, 2},
	{false, "19920521000000Z", "19920521000000Z", "1992-05-21T00:00:00Z", TimeZoneUTC, 0, TimeUnitSecond, 0},
	// comma decimal sign, and a fraction beyond nanoseconds (decision D3)
	{false, "20260101120000,5Z", "20260101120000.5Z", "2026-01-01T12:00:00.5Z", TimeZoneUTC, 0, TimeUnitSecond, 1},
	{false, "20260101120000.1234567891Z", "20260101120000.1234567891Z", "2026-01-01T12:00:00.123456789Z", TimeZoneUTC, 0, TimeUnitSecond, 10},
	{false, "20260101120000.1234567895Z", "20260101120000.1234567895Z", "2026-01-01T12:00:00.123456789Z", TimeZoneUTC, 0, TimeUnitSecond, 10},
	{false, "20261231235959.9999999999Z", "20261231235959.9999999999Z", "2026-12-31T23:59:59.999999999Z", TimeZoneUTC, 0, TimeUnitSecond, 10},
	// differential that crosses a year boundary; RFC 5280 "no expiry" value
	{false, "20260101003000+0100", "20251231233000Z", "2026-01-01T00:30:00+01:00", TimeZoneOffset, 60, TimeUnitSecond, 0},
	{false, "99991231235959Z", "99991231235959Z", "9999-12-31T23:59:59Z", TimeZoneUTC, 0, TimeUnitSecond, 0},
	{false, "99991231235959-0100", "", "9999-12-31T23:59:59-01:00", TimeZoneOffset, -60, TimeUnitSecond, 0},
	{false, "00000101003000+0100", "", "0000-01-01T00:30:00+01:00", TimeZoneOffset, 60, TimeUnitSecond, 0},
}

var invalidTimes = []struct {
	utc bool
	in  string
}{
	{false, "20260101240000Z"},     // §46.2 a) excludes midnight at the end of a day
	{false, "20261231235960Z"},     // leap second: decision D4
	{false, "20260101120000.Z"},    // decimal sign without digits
	{false, "20260101120000z"},     // §46.3 b) upper-case Z
	{false, "20260230120000Z"},     // no 30 February
	{false, "202601011Z"},          // odd digit count
	{false, "20260101120000+1"},    // differential needs hh
	{false, "20260101120000+2400"}, // differential hh 00-23 (decision D5)
	{false, "20260101120000+0160"}, // differential mm 00-59
	{false, "20260101120000Z+01"},  // nothing may follow Z
	{false, "20260101120000+"},
	{false, "2026-01-01T12:00:00Z"}, // RFC 3339 is not a §46.3 form
	{false, ""},
	{true, "260101120000"},    // §47.3 c) requires Z or a differential
	{true, "2601011200+01"},   // §47.3 c) 2) needs hhmm
	{true, "26010112Z"},       // §47.3 b) needs hhmm
	{true, "260101120000.5Z"}, // UTCTime has no fraction
	{true, "500229120000Z"},   // 1950 is not a leap year (window D1)
	{true, "260101240000Z"},   // §47.3 b) 1) hh is 00 to 23
	{true, "260101120000+2400"},
	{true, ""},
}

func TestTimeWorkedExamples(t *testing.T) {
	for _, e := range timeExamples {
		var (
			text, canon, jsonText string
			inst                  time.Time
			instErr, canonErr     error
			zone                  TimeZoneKind
			offset                int
			unit                  TimeUnit
			digits                int
			canonical             bool
		)
		if e.utc {
			v, err := ParseUTCTime(e.in)
			if err != nil {
				t.Fatalf("%q: %v", e.in, err)
			}
			text = v.String()
			c, err := v.Canonical()
			canon, canonErr, canonical = c.String(), err, v.IsCanonical()
			inst, instErr = v.Time()
			j, _ := json.Marshal(v)
			jsonText = string(j)
			zone, offset = v.Zone()
			unit, digits = v.Accuracy()
		} else {
			v, err := ParseGeneralizedTime(e.in)
			if err != nil {
				t.Fatalf("%q: %v", e.in, err)
			}
			text = v.String()
			c, err := v.Canonical()
			canon, canonErr, canonical = c.String(), err, v.IsCanonical()
			inst, instErr = v.Time()
			j, _ := json.Marshal(v)
			jsonText = string(j)
			zone, offset = v.Zone()
			unit, digits = v.Accuracy()
		}
		if text != e.in {
			t.Errorf("%q: String() = %q", e.in, text)
		}
		if jsonText != `"`+e.in+`"` {
			t.Errorf("%q: JSON = %s", e.in, jsonText)
		}
		if e.der == "" {
			if !errors.Is(canonErr, ErrNoCanonicalTime) {
				t.Errorf("%q: Canonical() = %q, %v; want ErrNoCanonicalTime", e.in, canon, canonErr)
			}
		} else if canonErr != nil || canon != e.der {
			t.Errorf("%q: Canonical() = %q, %v; want %q", e.in, canon, canonErr, e.der)
		}
		if canonical != (e.der == e.in) {
			t.Errorf("%q: IsCanonical() = %v", e.in, canonical)
		}
		if e.instant == "" {
			if !errors.Is(instErr, ErrLocalTime) {
				t.Errorf("%q: Time() = %v, %v; want ErrLocalTime", e.in, inst, instErr)
			}
		} else if instErr != nil || inst.Format(time.RFC3339Nano) != e.instant {
			t.Errorf("%q: Time() = %v, %v; want %s", e.in, inst.Format(time.RFC3339Nano), instErr, e.instant)
		}
		if zone != e.zone || offset != e.offset || unit != e.unit || digits != e.digits {
			t.Errorf("%q: Zone() = %d %d, Accuracy() = %d %d; want %d %d, %d %d", e.in, zone, offset, unit, digits, e.zone, e.offset, e.unit, e.digits)
		}
	}
}

func TestTimeInvalid(t *testing.T) {
	for _, c := range invalidTimes {
		var err error
		if c.utc {
			var v UTCTime
			v, err = ParseUTCTime(c.in)
			if !v.IsZero() {
				t.Errorf("%q: rejected value is not zero", c.in)
			}
		} else {
			var v GeneralizedTime
			v, err = ParseGeneralizedTime(c.in)
			if !v.IsZero() {
				t.Errorf("%q: rejected value is not zero", c.in)
			}
		}
		if !errors.Is(err, ErrTimeSyntax) {
			t.Errorf("%q accepted (err=%v)", c.in, err)
		}
	}
}

func TestGeneralizedTimeTimeIn(t *testing.T) {
	g, err := ParseGeneralizedTime("19851106210627.3")
	if err != nil {
		t.Fatal(err)
	}
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	got, err := g.TimeIn(newYork)
	if err != nil || got.UTC().Format(time.RFC3339Nano) != "1985-11-07T02:06:27.3Z" {
		t.Fatalf("TimeIn = %v, %v", got, err)
	}
	if _, err := g.TimeIn(nil); !errors.Is(err, ErrLocalTime) {
		t.Fatalf("TimeIn(nil) = %v", err)
	}
	// A value with a zone ignores loc, including nil.
	z, _ := ParseGeneralizedTime("19851106210627.3-0500")
	got, err = z.TimeIn(nil)
	if err != nil || got.UTC().Format(time.RFC3339Nano) != "1985-11-07T02:06:27.3Z" {
		t.Fatalf("TimeIn(nil) with differential = %v, %v", got, err)
	}
}

func TestTimeEqual(t *testing.T) {
	equal := [][2]string{
		{"2026010112,5Z", "2026010112.5Z"},
		{"20260101120000+01", "20260101120000+0100"},
		{"20260101120000-00", "20260101120000-0000"},
	}
	different := [][2]string{
		{"20260101120000Z", "20260101120000.0Z"},
		{"202601011200Z", "20260101120000Z"},
		{"20260101120000", "20260101120000Z"},
		{"20260101130000+0100", "20260101120000Z"},
		{"20260101120000-0000", "20260101120000Z"},
	}
	for _, p := range equal {
		a, _ := ParseGeneralizedTime(p[0])
		b, _ := ParseGeneralizedTime(p[1])
		if !a.Equal(b) || a == b {
			t.Errorf("%q vs %q: Equal=%v ==%v", p[0], p[1], a.Equal(b), a == b)
		}
	}
	for _, p := range different {
		a, _ := ParseGeneralizedTime(p[0])
		b, _ := ParseGeneralizedTime(p[1])
		if a.Equal(b) {
			t.Errorf("%q vs %q: Equal", p[0], p[1])
		}
	}
	u1, _ := ParseUTCTime("2601011200+0100")
	u2, _ := ParseUTCTime("2601011100Z")
	u3, _ := ParseUTCTime("2601011200+0100")
	if u1.Equal(u2) || !u1.Equal(u3) || u1 != u3 {
		t.Error("UTCTime Equal")
	}
	if !(UTCTime{}).Equal(UTCTime{}) || u1.Equal(UTCTime{}) || !(GeneralizedTime{}).Equal(GeneralizedTime{}) {
		t.Error("zero values")
	}
}

func TestTimeZeroValue(t *testing.T) {
	var g GeneralizedTime
	var u UTCTime
	if _, err := g.Time(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := g.TimeIn(time.UTC); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := g.Canonical(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := u.Time(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := u.Canonical(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if g.IsCanonical() || u.IsCanonical() {
		t.Fatal("zero value is canonical")
	}
	if kind, off := g.Zone(); kind != 0 || off != 0 {
		t.Fatal("zero Zone")
	}
	if unit, digits := u.Accuracy(); unit != 0 || digits != 0 {
		t.Fatal("zero Accuracy")
	}
	j, _ := json.Marshal(struct {
		G GeneralizedTime
		U UTCTime
	}{})
	if string(j) != `{"G":"","U":""}` {
		t.Fatal(string(j))
	}
	var back struct {
		G GeneralizedTime
		U UTCTime
	}
	if err := json.Unmarshal(j, &back); err != nil || !back.G.IsZero() || !back.U.IsZero() {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"G":"2026-01-01T12:00:00Z"}`), &back); !errors.Is(err, ErrTimeSyntax) {
		t.Fatalf("RFC 3339 JSON accepted: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"U":"2026-01-01T12:00:00Z"}`), &back); !errors.Is(err, ErrTimeSyntax) {
		t.Fatalf("RFC 3339 JSON accepted: %v", err)
	}
}

func TestTimeJSONRoundTrip(t *testing.T) {
	type record struct {
		NotBefore GeneralizedTime
		NotAfter  UTCTime
		Optional  *GeneralizedTime `json:",omitempty"`
	}
	in := record{}
	in.NotBefore, _ = ParseGeneralizedTime("19920722132100.30")
	in.NotAfter, _ = ParseUTCTime("8201020700-0500")
	j, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != `{"NotBefore":"19920722132100.30","NotAfter":"8201020700-0500"}` {
		t.Fatal(string(j))
	}
	var out record
	if err := json.Unmarshal(j, &out); err != nil || out != in {
		t.Fatalf("%+v %v", out, err)
	}
}

// A fraction is converted with linear-time decimal arithmetic, so a long
// fraction cannot make Canonical or IsCanonical expensive.
func TestGeneralizedTimeLongFraction(t *testing.T) {
	long := "2026010112." + strings.Repeat("9", 1<<20) + "Z"
	g, err := ParseGeneralizedTime(long)
	if err != nil {
		t.Fatal(err)
	}
	c, err := g.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// 0.999… hours = 3599.999…6 seconds: 12:59:59 plus the fraction.
	if !strings.HasPrefix(c.String(), "20260101125959.99999") || !strings.HasSuffix(c.String(), "64Z") {
		t.Fatalf("canonical prefix %q suffix %q", c.String()[:20], c.String()[len(c.String())-4:])
	}
	if g.IsCanonical() || !c.IsCanonical() {
		t.Fatal("IsCanonical")
	}
	mid := "2026010112." + strings.Repeat("1", 2000) + "Z"
	checkGeneralizedTime(t, mid)
}

// Independent oracles, written from the X.680 / X.690 text.
var (
	reGeneralized    = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})(?:([0-9]{2})([0-9]{2})?)?(?:[.,]([0-9]+))?(Z|[+-][0-9]{2}(?:[0-9]{2})?)?$`)
	reUTC            = regexp.MustCompile(`^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})?(Z|[+-][0-9]{4})$`)
	reDERGeneralized = regexp.MustCompile(`^[0-9]{14}(\.[0-9]*[1-9])?Z$`)
	reDERUTC         = regexp.MustCompile(`^[0-9]{12}Z$`)
)

func oracleNumber(s string) int {
	n := 0
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0 // empty optional group
	}
	return n
}

func oracleDate(y, mo, d int) bool {
	t := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC)
	return mo >= 1 && mo <= 12 && t.Year() == y && int(t.Month()) == mo && t.Day() == d
}

func oracleZone(z string) bool {
	if len(z) <= 1 {
		return true
	}
	return oracleNumber(z[1:3]) <= 23 && (len(z) == 3 || oracleNumber(z[3:5]) <= 59)
}

func oracleGeneralized(s string) bool {
	m := reGeneralized.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	if !oracleDate(oracleNumber(m[1]), oracleNumber(m[2]), oracleNumber(m[3])) || oracleNumber(m[4]) > 23 {
		return false
	}
	if m[5] != "" && oracleNumber(m[5]) > 59 || m[6] != "" && oracleNumber(m[6]) > 59 {
		return false
	}
	return oracleZone(m[8])
}

func oracleUTC(s string) bool {
	m := reUTC.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	y := oracleNumber(m[1]) + 1900
	if y < 1950 {
		y += 100
	}
	return oracleDate(y, oracleNumber(m[2]), oracleNumber(m[3])) && oracleNumber(m[4]) <= 23 && oracleNumber(m[5]) <= 59 &&
		(m[6] == "" || oracleNumber(m[6]) <= 59) && oracleZone(m[7])
}

// exactInstant computes UTC seconds since the Unix epoch as a big.Rat,
// independently of secondsOfDay and time.Date normalisation.
func exactInstant(s string) *big.Rat {
	m := reGeneralized.FindStringSubmatch(s)
	days := time.Date(oracleNumber(m[1]), time.Month(oracleNumber(m[2])), oracleNumber(m[3]), 0, 0, 0, 0, time.UTC).Unix() / 86400
	r := new(big.Rat).SetInt64(days*86400 + int64(oracleNumber(m[4]))*3600 + int64(oracleNumber(m[5]))*60 + int64(oracleNumber(m[6])))
	if m[7] != "" {
		f, _ := new(big.Rat).SetString("0." + m[7])
		unit := int64(1)
		switch {
		case m[5] == "":
			unit = 3600
		case m[6] == "":
			unit = 60
		}
		r.Add(r, f.Mul(f, new(big.Rat).SetInt64(unit)))
	}
	if z := m[8]; len(z) > 1 {
		off := int64(oracleNumber(z[1:3])) * 3600
		if len(z) == 5 {
			off += int64(oracleNumber(z[3:5])) * 60
		}
		if z[0] == '-' {
			off = -off
		}
		r.Sub(r, new(big.Rat).SetInt64(off))
	}
	return r
}

func checkGeneralizedTime(t *testing.T, s string) {
	t.Helper()
	g, err := ParseGeneralizedTime(s)
	if (err == nil) != oracleGeneralized(s) {
		t.Fatalf("%q: parser accepted=%v, oracle=%v (%v)", s, err == nil, oracleGeneralized(s), err)
	}
	if err != nil {
		if !errors.Is(err, ErrTimeSyntax) {
			t.Fatalf("%q: %v", s, err)
		}
		return
	}
	if g.String() != s {
		t.Fatalf("%q: String() = %q", s, g.String())
	}
	var back GeneralizedTime
	if txt, _ := g.MarshalText(); back.UnmarshalText(txt) != nil || back != g {
		t.Fatalf("%q: text round trip", s)
	}
	if j, err := json.Marshal(g); err != nil || json.Unmarshal(j, &back) != nil || back != g {
		t.Fatalf("%q: JSON round trip", s)
	}
	c, err := g.Canonical()
	zone, _ := g.Zone()
	if zone == TimeZoneLocal {
		if !errors.Is(err, ErrNoCanonicalTime) || g.IsCanonical() {
			t.Fatalf("%q: local time canonicalised to %q", s, c)
		}
		if _, err := g.Time(); !errors.Is(err, ErrLocalTime) {
			t.Fatalf("%q: local Time() = %v", s, err)
		}
		return
	}
	if err != nil {
		y := exactInstant(s)
		lo := new(big.Rat).SetInt64(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
		hi := new(big.Rat).SetInt64(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
		if !errors.Is(err, ErrNoCanonicalTime) || y.Cmp(lo) >= 0 && y.Cmp(hi) < 0 {
			t.Fatalf("%q: Canonical failed in range: %v", s, err)
		}
		return
	}
	if !reDERGeneralized.MatchString(c.String()) || !oracleGeneralized(c.String()) {
		t.Fatalf("%q: canonical %q violates X.690 §11.7", s, c)
	}
	if exactInstant(s).Cmp(exactInstant(c.String())) != 0 {
		t.Fatalf("%q: canonical %q is a different instant", s, c)
	}
	if cc, err := c.Canonical(); err != nil || cc != c || !c.IsCanonical() {
		t.Fatalf("%q: canonical not idempotent: %q %v", s, cc, err)
	}
	if g.IsCanonical() != (c == g) {
		t.Fatalf("%q: IsCanonical() = %v, canonical %q", s, g.IsCanonical(), c)
	}
	inst, err := g.Time()
	if err != nil {
		t.Fatalf("%q: Time: %v", s, err)
	}
	// Time() truncates beyond nanoseconds: the error is in [0, 1ns).
	diff := new(big.Rat).Sub(exactInstant(s), new(big.Rat).SetFrac64(inst.UnixNano(), 1e9))
	if inst.Year() > 1677 && inst.Year() < 2262 && (diff.Sign() < 0 || diff.Cmp(big.NewRat(1, 1e9)) >= 0) {
		t.Fatalf("%q: Time() off by %s s", s, diff.FloatString(12))
	}
}

func checkUTCTime(t *testing.T, s string) {
	t.Helper()
	u, err := ParseUTCTime(s)
	if (err == nil) != oracleUTC(s) {
		t.Fatalf("%q: parser accepted=%v, oracle=%v (%v)", s, err == nil, oracleUTC(s), err)
	}
	if err != nil {
		if !errors.Is(err, ErrTimeSyntax) {
			t.Fatalf("%q: %v", s, err)
		}
		return
	}
	if u.String() != s {
		t.Fatalf("%q: String() = %q", s, u.String())
	}
	var back UTCTime
	if j, err := json.Marshal(u); err != nil || json.Unmarshal(j, &back) != nil || back != u {
		t.Fatalf("%q: JSON round trip", s)
	}
	inst, _ := u.Time()
	c, err := u.Canonical()
	if err != nil {
		if y := inst.UTC().Year(); !errors.Is(err, ErrNoCanonicalTime) || y >= 1950 && y <= 2049 {
			t.Fatalf("%q: Canonical failed in window: %v", s, err)
		}
		return
	}
	if !reDERUTC.MatchString(c.String()) {
		t.Fatalf("%q: canonical %q violates X.690 §11.8", s, c)
	}
	if u.IsCanonical() != (c == u) || !c.IsCanonical() {
		t.Fatalf("%q: IsCanonical() = %v, canonical %q", s, u.IsCanonical(), c)
	}
	ci, _ := c.Time()
	if !ci.Equal(inst) {
		t.Fatalf("%q: canonical %q is %v, value is %v", s, c, ci, inst)
	}
	// Cross-check the instant against Go's own parser for the forms it knows.
	layout := "060102150405Z0700"
	if strings.IndexAny(s, "Z+-") == 10 {
		layout = "0601021504Z0700"
	}
	if g, err := time.Parse(layout, s); err == nil {
		if g.Year() >= 2050 && g.Year() <= 2068 {
			g = g.AddDate(-100, 0, 0)
		}
		if !g.Equal(inst) {
			t.Fatalf("%q: time.Parse=%v, Time()=%v", s, g, inst)
		}
	}
}

func TestTimePropertiesRandom(t *testing.T) {
	n := 300000
	if testing.Short() {
		n = 30000
	}
	r := rand.New(rand.NewSource(39))
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }
	d := func(n int) string {
		var b strings.Builder
		for range n {
			b.WriteByte(byte('0' + r.Intn(10)))
		}
		return b.String()
	}
	for range n {
		gt := fmt.Sprintf("%04d%02d%02d%02d", r.Intn(10000), r.Intn(14), r.Intn(33), r.Intn(26)) +
			pick("", fmt.Sprintf("%02d", r.Intn(62)), fmt.Sprintf("%02d%02d", r.Intn(62), r.Intn(62))) +
			pick("", "."+d(1+r.Intn(12)), ","+d(1+r.Intn(3)), ".") +
			pick("", "Z", "+"+d(2), "-"+d(4), "+"+d(3), "z")
		checkGeneralizedTime(t, gt)
		utc := d(6) + fmt.Sprintf("%02d%02d", r.Intn(25), r.Intn(61)) + pick("", d(2)) + pick("Z", "+"+d(4), "-"+d(4), "", "+"+d(2))
		checkUTCTime(t, utc)
	}
	// time.Time round trip
	for range n / 3 {
		tm := time.Unix(r.Int63n(253402300800+62167219200)-62167219200, r.Int63n(1e9)).In(time.FixedZone("", (r.Intn(49)-24)*1800))
		g, err := GeneralizedTimeFromTime(tm)
		if tm.UTC().Year() < 0 || tm.UTC().Year() > 9999 {
			if !errors.Is(err, ErrTimeRange) {
				t.Fatalf("%v accepted", tm)
			}
			continue
		}
		back, _ := g.Time()
		if err != nil || !back.Equal(tm) || !g.IsCanonical() {
			t.Fatalf("%v -> %q -> %v (%v)", tm, g, back, err)
		}
		u, err := UTCTimeFromTime(tm.Truncate(time.Second))
		if y := tm.UTC().Year(); y >= 1950 && y <= 2049 {
			ub, _ := u.Time()
			if err != nil || !ub.Equal(tm.Truncate(time.Second)) || !u.IsCanonical() {
				t.Fatalf("UTCTime %v -> %q (%v)", tm, u, err)
			}
		} else if !errors.Is(err, ErrTimeRange) {
			t.Fatalf("UTCTime %v accepted out of window: %q", tm, u)
		}
	}
}

func TestTimeFromTimeRange(t *testing.T) {
	if _, err := UTCTimeFromTime(time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC)); !errors.Is(err, ErrTimeRange) {
		t.Fatal(err)
	}
	for _, tm := range []time.Time{time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := UTCTimeFromTime(tm); !errors.Is(err, ErrTimeRange) {
			t.Fatal(tm, err)
		}
	}
	for _, tm := range []time.Time{time.Date(-1, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := GeneralizedTimeFromTime(tm); !errors.Is(err, ErrTimeRange) {
			t.Fatal(tm, err)
		}
	}
	g, err := GeneralizedTimeFromTime(time.Date(2026, 1, 1, 1, 0, 0, 120000000, time.FixedZone("", 3600)))
	if err != nil || g.String() != "20260101000000.12Z" {
		t.Fatal(g, err)
	}
	u, err := UTCTimeFromTime(time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || u.String() != "500101000000Z" {
		t.Fatal(u, err)
	}
	u, err = UTCTimeFromTime(time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC))
	if err != nil || u.String() != "491231235959Z" {
		t.Fatal(u, err)
	}
}

func FuzzParseGeneralizedTime(f *testing.F) {
	for _, e := range timeExamples {
		if !e.utc {
			f.Add(e.in)
		}
	}
	for _, c := range invalidTimes {
		f.Add(c.in)
	}
	f.Fuzz(func(t *testing.T, s string) { checkGeneralizedTime(t, s) })
}

func FuzzParseUTCTime(f *testing.F) {
	for _, e := range timeExamples {
		if e.utc {
			f.Add(e.in)
		}
	}
	for _, c := range invalidTimes {
		f.Add(c.in)
	}
	f.Fuzz(func(t *testing.T, s string) { checkUTCTime(t, s) })
}
