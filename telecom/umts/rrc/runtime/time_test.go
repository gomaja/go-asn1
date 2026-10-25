// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/time_test.go; SHA-256 fb6425e6e5e1622046460c8cf1a2f0a5d0fa56f5876dfca66e81539735c0b5a6.
package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Port of the UTCTime worked examples in go-asn1 f2c57b4 runtime/time_test.go.
// X.680 (02/2021) §47.3 and X.690 (02/2021) §11.8 govern lexical/canonical forms.
func TestUTCTimeWorkedExamples(t *testing.T) {
	for _, tc := range []struct {
		input, canonical, instant string
		zone                      TimeZoneKind
		offset                    int
		unit                      TimeUnit
	}{
		{"2601011200Z", "260101120000Z", "2026-01-01T12:00:00Z", TimeZoneUTC, 0, TimeUnitMinute},
		{"260101120000+0100", "260101110000Z", "2026-01-01T12:00:00+01:00", TimeZoneOffset, 60, TimeUnitSecond},
		{"8201020700-0500", "820102120000Z", "1982-01-02T07:00:00-05:00", TimeZoneOffset, -300, TimeUnitMinute},
		{"491231230000-0100", "", "2049-12-31T23:00:00-01:00", TimeZoneOffset, -60, TimeUnitSecond},
		{"500101003000+0100", "", "1950-01-01T00:30:00+01:00", TimeZoneOffset, 60, TimeUnitSecond},
		{"260101120000-0000", "260101120000Z", "2026-01-01T12:00:00Z", TimeZoneOffset, 0, TimeUnitSecond},
	} {
		t.Run(tc.input, func(t *testing.T) {
			value, err := ParseUTCTime(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if value.String() != tc.input || value.IsZero() {
				t.Fatal("lexical value changed")
			}
			if zone, offset := value.Zone(); zone != tc.zone || offset != tc.offset {
				t.Fatal("zone changed")
			}
			if unit, digits := value.Accuracy(); unit != tc.unit || digits != 0 {
				t.Fatal("accuracy changed")
			}
			instant, err := value.Time()
			if err != nil || instant.Format(time.RFC3339) != tc.instant {
				t.Fatalf("instant %v %v", instant, err)
			}
			canonical, err := value.Canonical()
			if tc.canonical == "" {
				if !errors.Is(err, ErrNoCanonicalTime) {
					t.Fatal(err)
				}
			} else if err != nil || canonical.String() != tc.canonical || !canonical.IsCanonical() {
				t.Fatalf("canonical %v %v", canonical, err)
			}
			text, err := value.MarshalText()
			if err != nil || !bytes.Equal(text, []byte(tc.input)) {
				t.Fatal("text changed")
			}
			var decoded UTCTime
			if err := decoded.UnmarshalText(text); err != nil || !decoded.Equal(value) {
				t.Fatal("text replay changed", err)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != value {
				t.Fatal("JSON replay changed", err)
			}
		})
	}
}

func TestUTCTimeInvalidAndUnset(t *testing.T) {
	for _, text := range []string{"260101120000", "2601011200+01", "26010112Z", "260101120000.5Z", "500229120000Z", "260101240000Z", "260101120000+2400", ""} {
		if _, err := ParseUTCTime(text); !errors.Is(err, ErrTimeSyntax) {
			t.Fatalf("accepted %q", text)
		}
	}
	var value UTCTime
	if !value.IsZero() || value.IsCanonical() || !value.Equal(UTCTime{}) {
		t.Fatal("unset state")
	}
	if _, err := value.Time(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if _, err := value.Canonical(); !errors.Is(err, ErrTimeNotSet) {
		t.Fatal(err)
	}
	if err := value.UnmarshalText(nil); err != nil || !value.IsZero() {
		t.Fatal(err)
	}
	valid, _ := ParseUTCTime("260101120000Z")
	value = valid
	if err := value.UnmarshalText([]byte("invalid")); !errors.Is(err, ErrTimeSyntax) || value != valid {
		t.Fatal("failed decode replaced value")
	}
	if _, err := UTCTimeFromTime(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrTimeRange) {
		t.Fatal(err)
	}
	if _, err := UTCTimeFromTime(time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC)); !errors.Is(err, ErrTimeRange) {
		t.Fatal(err)
	}
}

func TestUTCTimeMinuteDifferentialAndSharedFractionArithmetic(t *testing.T) {
	value, err := ParseUTCTime("260101120000+0130")
	if err != nil {
		t.Fatal(err)
	}
	if _, offset := value.Zone(); offset != 90 {
		t.Fatal("minute differential lost")
	}
	// The port retains the shared calendar arithmetic without weakening its guards.
	f := timeFields{hour: 1, unit: TimeUnitMinute, fraction: "5"}
	if seconds, fraction := f.secondsOfDay(); seconds != 3630 || fraction != "" {
		t.Fatal(seconds, fraction)
	}
}
