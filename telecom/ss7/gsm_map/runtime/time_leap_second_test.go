// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/time_leap_second_test.go; SHA-256 6991265ff85e68c913ba6b77eaac7f136b0f03f17256e507bee55d9ae01aac1e.
package runtime

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// X.680 (02/2021) §46.3 imports ISO 8601's positive leap second;
// X.690 (02/2021) §11.7 canonicalizes its zone without changing second 60.
func TestGeneralizedTimeLeapSecond(t *testing.T) {
	for _, tc := range []struct {
		text, canonical string
		zone            TimeZoneKind
		offset, digits  int
	}{
		{"20161231235960Z", "20161231235960Z", TimeZoneUTC, 0, 0},
		{"20161231235960.500Z", "20161231235960.5Z", TimeZoneUTC, 0, 3},
		{"20161231235960,500Z", "20161231235960.5Z", TimeZoneUTC, 0, 3},
		{"20170101005960+0100", "20161231235960Z", TimeZoneOffset, 60, 0},
		{"20170301002960+01", "20170228232960Z", TimeZoneOffset, 60, 0},
		{"20160301002960+0100", "20160229232960Z", TimeZoneOffset, 60, 0},
		{"20160101002960.5+0100", "20151231232960.5Z", TimeZoneOffset, 60, 1},
		{"20161231232960-0100", "20170101002960Z", TimeZoneOffset, -60, 0},
		{"20160131235960-0100", "20160201005960Z", TimeZoneOffset, -60, 0},
		{"20161230125960Z", "20161230125960Z", TimeZoneUTC, 0, 0},
		{"20161230123460.1234567890123Z", "20161230123460.1234567890123Z", TimeZoneUTC, 0, 13},
		{"20161230123460", "", TimeZoneLocal, 0, 0},
		{"20161230123460.5", "", TimeZoneLocal, 0, 1},
	} {
		t.Run(tc.text, func(t *testing.T) {
			g, err := ParseGeneralizedTime(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if g.IsZero() || g.String() != tc.text {
				t.Fatalf("lexical value = %q", g)
			}
			if zone, offset := g.Zone(); zone != tc.zone || offset != tc.offset {
				t.Fatalf("Zone() = %d, %d", zone, offset)
			}
			if unit, digits := g.Accuracy(); unit != TimeUnitSecond || digits != tc.digits {
				t.Fatalf("Accuracy() = %d, %d", unit, digits)
			}
			text, err := g.MarshalText()
			var back GeneralizedTime
			if err != nil || string(text) != tc.text || back.UnmarshalText(text) != nil || back != g || !back.Equal(g) {
				t.Fatalf("text round trip = %q, %v", text, err)
			}
			for _, convert := range []func() (time.Time, error){g.Time, func() (time.Time, error) { return g.TimeIn(time.UTC) }, func() (time.Time, error) { return g.TimeIn(nil) }} {
				instant, err := convert()
				if !errors.Is(err, ErrTimeRange) || !instant.IsZero() || !strings.Contains(err.Error(), "leap second") {
					t.Fatalf("conversion = %v, %v; want explicit leap second error", instant, err)
				}
			}
			canonical, err := g.Canonical()
			if tc.canonical == "" {
				if !errors.Is(err, ErrNoCanonicalTime) || g.IsCanonical() {
					t.Fatalf("local Canonical() = %q, %v", canonical, err)
				}
			} else {
				if err != nil || canonical.String() != tc.canonical || g.IsCanonical() != (tc.text == tc.canonical) || !canonical.IsCanonical() {
					t.Fatalf("Canonical() = %q, %v; want %q", canonical, err, tc.canonical)
				}
				if again, err := canonical.Canonical(); err != nil || again != canonical {
					t.Fatalf("canonical not idempotent: %q, %v", again, err)
				}
			}
		})
	}
	for _, text := range []string{"20161231235961Z", "20161231235999Z", "20161230123461.5", "20161230123461-05"} {
		if _, err := ParseGeneralizedTime(text); !errors.Is(err, ErrTimeSyntax) {
			t.Errorf("second above 60: %q: %v", text, err)
		}
	}
	if _, err := ParseUTCTime("161231235960Z"); !errors.Is(err, ErrTimeSyntax) {
		t.Fatalf("UTCTime second 60: %v", err)
	}
	for _, pair := range [][2]string{{"20161231235960Z", "20170101000000Z"}, {"20161231235960.5Z", "20170101000000.5Z"}, {"20161230123460Z", "20161230123500Z"}} {
		a, errA := ParseGeneralizedTime(pair[0])
		b, errB := ParseGeneralizedTime(pair[1])
		if errA != nil || errB != nil || a.Equal(b) || b.Equal(a) {
			t.Fatalf("leap second equated with next minute: %q, %q (%v, %v)", a, b, errA, errB)
		}
	}
	a, _ := ParseGeneralizedTime("20161231235960.5+01")
	b, _ := ParseGeneralizedTime("20161231235960,5+0100")
	if !a.Equal(b) || !b.Equal(a) {
		t.Fatal("decimal sign and differential spelling changed abstract value")
	}
	for _, text := range []string{"00000101002960+0100", "99991231232960-0100"} {
		g, err := ParseGeneralizedTime(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Canonical(); !errors.Is(err, ErrNoCanonicalTime) {
			t.Fatalf("out of range Canonical(%q): %v", text, err)
		}
	}
}

func TestGeneralizedTimeLeapSecondOracleBounds(t *testing.T) {
	for _, text := range []string{"00000101005960+0100", "00000101000060+0001", "00000101000060-0001", "99991231235960Z"} {
		checkGeneralizedTime(t, text)
	}
}
