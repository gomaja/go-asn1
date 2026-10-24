// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/time.go; SHA-256 eb4f03bda9708f902e26de34f76d4b084b636cb433a2713b1ee0082d60961ae4.
package runtime

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UTCTime holds the validated X.680 (02/2021) §47.3 lexical form. The
// canonical PER form follows X.691 (02/2021) §10.6.5 and X.690 §11.8.

var (
	// ErrTimeSyntax reports a string outside X.680 (02/2021) §47.3.
	ErrTimeSyntax = errors.New("asn1: invalid time lexical form")
	// ErrNoCanonicalTime reports a UTC equivalent outside the UTCTime window.
	ErrNoCanonicalTime = errors.New("asn1: time has no canonical DER/PER form")
	// ErrTimeRange reports a time.Time that the type cannot represent exactly.
	ErrTimeRange = errors.New("asn1: time outside the range of the type")
	// ErrTimeNotSet reports use of a zero value, which means "not set".
	ErrTimeNotSet = errors.New("asn1: time value not set")
)

// TimeZoneKind is the zone component of an abstract time value
// (X.680 (02/2021) §46.2 a)–c), §47.2 c)).
type TimeZoneKind uint8

const (
	// TimeZoneLocal is a local time of day with no differential
	// (X.680 (02/2021) §46.3 a)); GeneralizedTime only.
	TimeZoneLocal TimeZoneKind = iota + 1
	// TimeZoneUTC is "Z" (X.680 (02/2021) §46.3 b), §47.3 c) 1)).
	TimeZoneUTC
	// TimeZoneOffset is a differential ±hh[mm] from UTC
	// (X.680 (02/2021) §46.3 c), §47.3 c) 2)).
	TimeZoneOffset
)

// TimeUnit is the least significant time component present
// (X.680 (02/2021) §46.2 a) 1)–3), §47.3 b)).
type TimeUnit uint8

const (
	TimeUnitHour TimeUnit = iota + 1
	TimeUnitMinute
	TimeUnitSecond
)

// UTCTime is a validated X.680 (02/2021) §47.3 value, held as its lexical
// form. YY is read with the RFC 5280 §4.1.2.5.1 window: 50–99 are 1950–1999
// and 00–49 are 2000–2049. The zero value means "not set" and every encoder
// rejects it. == compares lexical identity; Equal compares abstract values.
type UTCTime struct{ text string }

// timeFields is the abstract value: the decimal sign and the spelling of a
// whole-hour differential are not part of it (X.690 (02/2021) §11.9.1 a), b)).
type timeFields struct {
	year, month, day, hour, minute, second int
	unit                                   TimeUnit
	fraction                               string // digits of the last unit's fraction, verbatim
	zone                                   TimeZoneKind
	offset                                 int // minutes east of UTC
}

func allDigits(s string) bool {
	return s != "" && leadingDigits(s) == len(s)
}

func isNotDigit(r rune) bool { return r < '0' || r > '9' }

// leadingDigits returns the length of the run of decimal digits that starts s.
func leadingDigits(s string) int {
	if end := strings.IndexFunc(s, isNotDigit); end >= 0 {
		return end
	}
	return len(s)
}

// digitsValue reads a field of two or four decimal digits, already checked
// by allDigits.
func digitsValue(s string) int {
	value, _ := strconv.Atoi(s)
	return value
}

// validRanges checks X.680 (02/2021) §46.2 a) (midnight at the end of a day
// excluded), §47.3 a)–b), and rejects a leap second.
func (f *timeFields) validRanges() bool {
	if f.month < 1 || f.month > 12 || f.day < 1 || f.hour > 23 || f.minute > 59 || f.second > 59 {
		return false
	}
	lastDay := time.Date(f.year, time.Month(f.month+1), 0, 0, 0, 0, 0, time.UTC).Day()
	return f.day <= lastDay
}

// parseTimeZone parses "" (local, GeneralizedTime only), "Z", "±hh"
// (GeneralizedTime only, X.680 (02/2021) §46.3 c)) or "±hhmm". Any hh 00–23
// and mm 00–59 is accepted, including -0000 (§47.3 c) 2)).
func parseTimeZone(s string, allowLocal, allowHours bool) (TimeZoneKind, int, bool) {
	switch {
	case s == "":
		return TimeZoneLocal, 0, allowLocal
	case s == "Z":
		return TimeZoneUTC, 0, true
	case s[0] != '+' && s[0] != '-':
		return 0, 0, false
	}
	body := s[1:]
	if !allDigits(body) || len(body) != 4 && (!allowHours || len(body) != 2) {
		return 0, 0, false
	}
	hours, minutes := digitsValue(body[:2]), 0
	if len(body) == 4 {
		minutes = digitsValue(body[2:])
	}
	if hours > 23 || minutes > 59 {
		return 0, 0, false
	}
	offset := hours*60 + minutes
	if s[0] == '-' {
		offset = -offset
	}
	return TimeZoneOffset, offset, true
}

func timeSyntaxError(kind, s string) error {
	return fmt.Errorf("%w: %s %q", ErrTimeSyntax, kind, s)
}

// parseUTCFields applies X.680 (02/2021) §47.3 a)–c): YYMMDDhhmm[ss](Z|±hhmm).
// X.680 gives only the two low-order digits of the year; RFC 5280
// §4.1.2.5.1 reads 50–99 as 19YY and 00–49 as 20YY, and that window applies
// to every UTCTime here.
func parseUTCFields(s string) (timeFields, error) {
	var f timeFields
	count := leadingDigits(s)
	if count != 10 && count != 12 {
		return f, timeSyntaxError("UTCTime", s)
	}
	century := "20"
	if s[0] >= '5' {
		century = "19"
	}
	f.year, f.month, f.day = digitsValue(century+s[:2]), digitsValue(s[2:4]), digitsValue(s[4:6])
	f.hour, f.minute, f.unit = digitsValue(s[6:8]), digitsValue(s[8:10]), TimeUnitMinute
	if count == 12 {
		f.second, f.unit = digitsValue(s[10:12]), TimeUnitSecond
	}
	var ok bool
	if f.zone, f.offset, ok = parseTimeZone(s[count:], false, false); !ok || !f.validRanges() {
		return f, timeSyntaxError("UTCTime", s)
	}
	return f, nil
}

// ParseUTCTime validates s against X.680 (02/2021) §47.3 and keeps it
// verbatim. The calendar date is checked in the RFC 5280 §4.1.2.5.1 window.
func ParseUTCTime(s string) (UTCTime, error) {
	if _, err := parseUTCFields(s); err != nil {
		return UTCTime{}, err
	}
	return UTCTime{text: s}, nil
}

// String returns the exact lexical form, or "" when not set.
func (u UTCTime) String() string { return u.text }

// IsZero reports whether the value is not set.
func (u UTCTime) IsZero() bool { return u.text == "" }

func (u UTCTime) fields() timeFields {
	f, _ := parseUTCFields(u.text)
	return f
}

// Zone reports the zone kind and, for TimeZoneOffset, the differential in
// minutes east of UTC. It returns (0, 0) when the value is not set.
func (u UTCTime) Zone() (kind TimeZoneKind, offsetMinutes int) {
	if u.IsZero() {
		return 0, 0
	}
	f := u.fields()
	return f.zone, f.offset
}

// Accuracy reports TimeUnitMinute or TimeUnitSecond; UTCTime has no fraction.
// It returns (0, 0) when the value is not set.
func (u UTCTime) Accuracy() (unit TimeUnit, fractionDigits int) {
	if u.IsZero() {
		return 0, 0
	}
	return u.fields().unit, 0
}

// Equal reports whether both carry the same abstract value: the same
// calendar date, time, accuracy, zone kind and differential. Two unset
// values are equal.
func (u UTCTime) Equal(other UTCTime) bool {
	if u.IsZero() || other.IsZero() {
		return u.IsZero() && other.IsZero()
	}
	return u.fields() == other.fields()
}

var timeUnitSeconds = [...]int{TimeUnitHour: 3600, TimeUnitMinute: 60, TimeUnitSecond: 1}

// secondsOfDay returns the whole seconds since the start of the stated day
// and the remaining fraction of a second as decimal digits without trailing
// zeros. The fraction of the last unit is multiplied by 3600, 60 or 1 digit
// by digit, so the conversion is exact for any number of digits and takes
// linear time.
func (f timeFields) secondsOfDay() (int, string) {
	seconds := f.hour*3600 + f.minute*60 + f.second
	if f.fraction == "" {
		return seconds, ""
	}
	multiplier := timeUnitSeconds[f.unit]
	scaled := []byte(f.fraction)
	carry := 0
	for i := len(scaled) - 1; i >= 0; i-- {
		product := int(scaled[i]-'0')*multiplier + carry
		scaled[i] = byte('0' + product%10)
		carry = product / 10
	}
	return seconds + carry, strings.TrimRight(string(scaled), "0")
}

// nanoseconds truncates a fraction of a second toward the earlier instant.
func nanoseconds(fraction string) int {
	padded := fraction + "000000000"
	value, _ := strconv.Atoi(padded[:9])
	return value
}

func (f timeFields) location() *time.Location {
	if f.zone == TimeZoneUTC {
		return time.UTC
	}
	return time.FixedZone("", f.offset*60)
}

func (f timeFields) wallClock(loc *time.Location) time.Time {
	seconds, fraction := f.secondsOfDay()
	return time.Date(f.year, time.Month(f.month), f.day, 0, 0, seconds, nanoseconds(fraction), loc)
}

// Time returns the instant, reading YY with the RFC 5280 §4.1.2.5.1 window,
// in time.UTC for "Z" and in a fixed zone for a differential.
func (u UTCTime) Time() (time.Time, error) {
	if u.IsZero() {
		return time.Time{}, ErrTimeNotSet
	}
	f := u.fields()
	return f.wallClock(f.location()), nil
}

// Canonical returns the X.690 (02/2021) §11.8 form YYMMDDhhmmssZ: UTC with
// "Z" (§11.8.1) and seconds present (§11.8.2). A UTC equivalent outside the
// RFC 5280 §4.1.2.5.1 window 1950–2049 returns ErrNoCanonicalTime; RFC 5280
// §4.1.2.5 requires GeneralizedTime from 2050.
func (u UTCTime) Canonical() (UTCTime, error) {
	if u.IsZero() {
		return UTCTime{}, ErrTimeNotSet
	}
	f := u.fields()
	t := f.wallClock(f.location())
	canonical, err := UTCTimeFromTime(t)
	if err != nil {
		return UTCTime{}, fmt.Errorf("%w: UTCTime %q is %s in UTC, outside the window 1950-2049", ErrNoCanonicalTime, u.text, t.UTC().Format(time.RFC3339))
	}
	return canonical, nil
}

// IsCanonical reports whether the value already is its X.690 (02/2021) §11.8
// form YYMMDDhhmmssZ.
func (u UTCTime) IsCanonical() bool {
	if u.IsZero() {
		return false
	}
	f := u.fields()
	return f.zone == TimeZoneUTC && f.unit == TimeUnitSecond
}

// UTCTimeFromTime returns the canonical X.690 (02/2021) §11.8 form
// YYMMDDhhmmssZ of t. UTCTime has no fraction of a second, and a UTC year
// outside the RFC 5280 §4.1.2.5.1 window 1950–2049 returns ErrTimeRange.
func UTCTimeFromTime(t time.Time) (UTCTime, error) {
	t = t.UTC()
	if t.Year() < 1950 || t.Year() > 2049 {
		return UTCTime{}, fmt.Errorf("%w: UTCTime year %d is outside 1950-2049", ErrTimeRange, t.Year())
	}
	if t.Nanosecond() != 0 {
		return UTCTime{}, fmt.Errorf("%w: UTCTime has no fraction of a second", ErrTimeRange)
	}
	return UTCTime{text: t.Format("060102150405Z")}, nil
}

// MarshalText returns the exact lexical form, or "" when not set.
func (u UTCTime) MarshalText() ([]byte, error) { return []byte(u.text), nil }

// UnmarshalText sets the value from its lexical form; "" clears it. Any
// other text must satisfy X.680 (02/2021) §47.3.
func (u *UTCTime) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*u = UTCTime{}
		return nil
	}
	value, err := ParseUTCTime(string(text))
	if err != nil {
		return err
	}
	*u = value
	return nil
}
