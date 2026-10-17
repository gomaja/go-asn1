// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/time.go; SHA-256 37ee95854474363fcdf5424cd1ca6aa11199c49122acf835b74d05e691e10fca.
package runtime

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrTimeSyntax reports a string outside X.680 (02/2021) §46.3 or §47.3.
	ErrTimeSyntax = errors.New("asn1: invalid time lexical form")
	// ErrLocalTime reports a GeneralizedTime local time of day with no
	// differential (X.680 (02/2021) §46.3 a)). It fixes no instant.
	ErrLocalTime = errors.New("asn1: local time of day without a UTC differential")
	// ErrNoCanonicalTime reports a value that X.690 (02/2021) §11.7/§11.8
	// cannot represent: a local time of day, or a UTC equivalent outside the
	// years of the type.
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

// GeneralizedTime is a validated X.680 (02/2021) §46.3 value, held as its
// lexical form. The zero value means "not set" and every encoder rejects it.
// == compares lexical identity; Equal compares abstract values.
type GeneralizedTime struct{ text string }

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

// parseGeneralizedFields applies X.680 (02/2021) §46.3 a)–c):
// YYYYMMDDhh[mm[ss]][(.|,)f+][Z|±hh[mm]].
func parseGeneralizedFields(s string) (timeFields, error) {
	var f timeFields
	if len(s) < 10 || !allDigits(s[:10]) {
		return f, timeSyntaxError("GeneralizedTime", s)
	}
	f.year, f.month, f.day, f.hour = digitsValue(s[:4]), digitsValue(s[4:6]), digitsValue(s[6:8]), digitsValue(s[8:10])
	rest := s[10:]
	switch leadingDigits(rest) {
	case 0:
		f.unit = TimeUnitHour
	case 2:
		f.unit, f.minute, rest = TimeUnitMinute, digitsValue(rest[:2]), rest[2:]
	case 4:
		f.unit, f.minute, f.second, rest = TimeUnitSecond, digitsValue(rest[:2]), digitsValue(rest[2:4]), rest[4:]
	default:
		return f, timeSyntaxError("GeneralizedTime", s)
	}
	if rest != "" && (rest[0] == '.' || rest[0] == ',') {
		digits := rest[1:]
		count := leadingDigits(digits)
		// ISO 8601, cited by X.680 (02/2021) §46.3 a) 2), requires a digit
		// after the decimal sign.
		if count == 0 {
			return f, timeSyntaxError("GeneralizedTime", s)
		}
		f.fraction, rest = digits[:count], digits[count:]
	}
	var ok bool
	if f.zone, f.offset, ok = parseTimeZone(rest, true, true); !ok || !f.validRanges() {
		return f, timeSyntaxError("GeneralizedTime", s)
	}
	return f, nil
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

// ParseGeneralizedTime validates s against X.680 (02/2021) §46.3 and keeps
// it verbatim. A leap second (60) is rejected.
func ParseGeneralizedTime(s string) (GeneralizedTime, error) {
	if _, err := parseGeneralizedFields(s); err != nil {
		return GeneralizedTime{}, err
	}
	return GeneralizedTime{text: s}, nil
}

// ParseUTCTime validates s against X.680 (02/2021) §47.3 and keeps it
// verbatim. The calendar date is checked in the RFC 5280 §4.1.2.5.1 window.
func ParseUTCTime(s string) (UTCTime, error) {
	if _, err := parseUTCFields(s); err != nil {
		return UTCTime{}, err
	}
	return UTCTime{text: s}, nil
}

// IsZero reports whether the value is not set.
func (g GeneralizedTime) IsZero() bool { return g.text == "" }

// IsZero reports whether the value is not set.
func (u UTCTime) IsZero() bool { return u.text == "" }

// fields returns the abstract value. Every non-zero value was validated
// when it was constructed.
func (g GeneralizedTime) fields() timeFields {
	f, _ := parseGeneralizedFields(g.text)
	return f
}

func (u UTCTime) fields() timeFields {
	f, _ := parseUTCFields(u.text)
	return f
}

// IsCanonical reports whether the value already is its X.690 (02/2021) §11.7
// form. With "Z" and seconds present, the conversion of Canonical changes
// only the decimal sign and trailing fraction zeros, so this check is
// lexical and linear.
func (g GeneralizedTime) IsCanonical() bool {
	if g.IsZero() {
		return false
	}
	f := g.fields()
	if f.zone != TimeZoneUTC || f.unit != TimeUnitSecond {
		return false
	}
	return f.fraction == "" || g.text[14] == '.' && !strings.HasSuffix(f.fraction, "0")
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
