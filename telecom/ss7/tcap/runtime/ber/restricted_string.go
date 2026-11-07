// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/restricted_string.go; SHA-256 f56050f7d1b663132168c033a86af0f20ebb6c7193edbd96e6642357e91c23d2.
package ber

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"time"
	"unicode/utf8"
)

// X.690 (02/2021) §§8.23.1, 8.23.4–8.23.5 and Table 3;
// X.680 (02/2021) §41.2 Table 9: NumericString is "Digits" and "Space".
// §41.4 Table 10: PrintableString is A–Z, a–z, 0–9, space and '()+,-./:=?.
// §41.1 Table 8: IA5String is registration 1 and 6 plus SPACE and DELETE;
// VisibleString is registration 6 plus SPACE. X.690 Table 3 assumes those
// repertoires and forbids explicit escape sequences for these four types.
func alphabetOctet(number int, b byte) bool {
	switch number {
	case tag.TagNumericString:
		return b == ' ' || b >= '0' && b <= '9'
	case tag.TagPrintableString:
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' {
			return true
		}
		switch b {
		case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
			return true
		}
		return false
	case tag.TagIA5String:
		return b <= 0x7f
	case tag.TagVisibleString:
		return b >= 0x20 && b <= 0x7e
	}
	return true
}

func alphabetRule(number int) string {
	switch number {
	case tag.TagNumericString:
		return "NumericString digits and space (X.680 (02/2021) §41.2 Table 9; X.690 (02/2021) §8.23.4)"
	case tag.TagPrintableString:
		return "PrintableString alphabet (X.680 (02/2021) §41.4 Table 10; X.690 (02/2021) §8.23.4)"
	case tag.TagIA5String:
		return "IA5String repertoire (X.680 (02/2021) Table 8; X.690 (02/2021) §8.23.5 Table 3)"
	default:
		return "VisibleString repertoire (X.680 (02/2021) Table 8; X.690 (02/2021) §8.23.5 Table 3)"
	}
}

func isAlphabetString(number int) bool {
	return number == tag.TagNumericString || number == tag.TagPrintableString || number == tag.TagIA5String || number == tag.TagVisibleString
}

func isCheckedRestrictedString(number int) bool {
	// X.680 (02/2021) Table 8 and §§46.3–47.3 put these tags in 18–30.
	// Ordinary universal primitives leave before alphabet dispatch.
	if number < tag.TagNumericString || number > tag.TagBMPString {
		return false
	}

	return isAlphabetString(number) || number == tag.TagBMPString || number == tag.TagUniversalString || number == tag.TagUTCTime || number == tag.TagGeneralizedTime
}

// restrictedStringState consumes the logical contents across OCTET STRING
// leaves (X.690 (02/2021) §§8.23.3, 8.23.6). Such leaves cannot contain
// another restricted-string root, so a scan needs only one local state;
// no frame fields or concatenation buffer are needed.
type restrictedStringState struct {
	number   int
	scalar   uint32
	pending  byte
	invalid  bool
	clock    restrictedTimeSyntax
	controls stringControlState
}

func (s *restrictedStringState) consume(contents []byte) {
	switch s.number {
	case tag.TagBMPString, tag.TagUniversalString:
		// X.690 (02/2021) §§8.23.7–8.23.8 require four-octet canonical
		// UniversalString and two-octet BMP forms, containing scalar values.
		width := byte(2)
		if s.number == tag.TagUniversalString {
			width = 4
		}
		for _, b := range contents {
			s.scalar = s.scalar<<8 | uint32(b)
			s.pending++
			if s.pending == width {
				// X.680 (02/2021) §41.15: BMPString ends at cell U+FFFD.
				if s.scalar > utf8.MaxRune || !utf8.ValidRune(rune(s.scalar)) || s.number == tag.TagBMPString && s.scalar > 0xfffd {
					s.invalid = true
				}
				if s.controls.consume(s.number, rune(s.scalar)) {
					s.invalid = true
				}
				s.scalar, s.pending = 0, 0
			}
		}
	case tag.TagUTCTime, tag.TagGeneralizedTime:
		s.clock.consume(contents)
	default:
		for _, b := range contents {
			if !alphabetOctet(s.number, b) || s.number == tag.TagIA5String && s.controls.consume(s.number, rune(b)) {
				s.invalid = true
			}
		}
	}
}

func (s *restrictedStringState) finish() error {
	if s.invalid || s.pending != 0 {
		switch s.number {
		case tag.TagBMPString:
			return fmt.Errorf("%w: BMPString requires whole two-octet values in its repertoire (X.680 (02/2021) §41.15; X.690 (02/2021) §§8.23.8–8.23.9)", ErrInvalidValue)
		case tag.TagUniversalString:
			return fmt.Errorf("%w: UniversalString requires whole four-octet Unicode scalar values (X.690 (02/2021) §§8.23.7, 8.23.9)", ErrInvalidValue)
		default:
			return fmt.Errorf("%w: %s", ErrInvalidValue, alphabetRule(s.number))
		}
	}
	if s.number == tag.TagUTCTime || s.number == tag.TagGeneralizedTime {
		if !s.clock.valid(s.number == tag.TagUTCTime) {
			return fmt.Errorf("%w: invalid time syntax (X.680 (02/2021) §§46.3, 47.3; X.690 (02/2021) §8.25)", ErrInvalidValue)
		}
	}
	return nil
}

func validateRestrictedStringContents(number int, contents []byte) error {
	state := restrictedStringState{number: number}
	state.consume(contents)
	return state.finish()
}

// X.680 (02/2021) §46.3: YYYYMMDDhh[mm[ss]][(.|,)digits][Z|±hh[mm]];
// §47.3: YYMMDDhhmm[ss](Z|±hhmm). Fractions have arbitrary precision.
// Retain only the bounded calendar and zone digits; consume fractional digits
// without storing them, including when a fraction crosses segment boundaries.
type restrictedTimeSyntax struct {
	digits        [14]byte
	zone          [4]byte
	count         byte
	zoneCount     byte
	phase         byte // 0 calendar, 1 fraction, 2 differential, 3 Z, 4 invalid
	fraction      bool
	fractionDigit bool
}

func (s *restrictedTimeSyntax) consume(contents []byte) {
	for _, b := range contents {
		switch s.phase {
		case 0:
			if b >= '0' && b <= '9' {
				if int(s.count) == len(s.digits) {
					s.phase = 4
				} else {
					s.digits[s.count] = b
					s.count++
				}
				continue
			}
			if b == '.' || b == ',' {
				s.phase = 1
				s.fraction = true
				continue
			}
		case 1:
			if b >= '0' && b <= '9' {
				s.fractionDigit = true
				continue
			}
		case 2:
			if b >= '0' && b <= '9' && int(s.zoneCount) < len(s.zone) {
				s.zone[s.zoneCount] = b
				s.zoneCount++
				continue
			}
			s.phase = 4
			continue
		default:
			s.phase = 4
			continue
		}
		switch b {
		case 'Z':
			s.phase = 3
		case '+', '-':
			s.phase = 2
		default:
			s.phase = 4
		}
	}
}

func timeDigitPair(a, b byte) int { return int(a-'0')*10 + int(b-'0') }

func (s *restrictedTimeSyntax) valid(utc bool) bool {
	if s.phase == 4 || s.fraction && !s.fractionDigit {
		return false
	}
	start := 0
	year := 0
	if utc {
		if s.count != 10 && s.count != 12 || s.fraction || s.phase != 2 && s.phase != 3 {
			return false
		}
		year = timeDigitPair(s.digits[0], s.digits[1])
		// Preserve the typed runtime's century interpretation for leap days.
		if year >= 50 {
			year += 1900
		} else {
			year += 2000
		}
	} else {
		if s.count != 10 && s.count != 12 && s.count != 14 {
			return false
		}
		year = timeDigitPair(s.digits[0], s.digits[1])*100 + timeDigitPair(s.digits[2], s.digits[3])
		start = 2
	}
	month := timeDigitPair(s.digits[start+2], s.digits[start+3])
	day := timeDigitPair(s.digits[start+4], s.digits[start+5])
	hour := timeDigitPair(s.digits[start+6], s.digits[start+7])
	minute, second := 0, 0
	if int(s.count) > start+8 {
		minute = timeDigitPair(s.digits[start+8], s.digits[start+9])
	}
	if int(s.count) > start+10 {
		second = timeDigitPair(s.digits[start+10], s.digits[start+11])
	}
	// Match the typed parser's existing seconds range. GeneralizedTime leap
	// seconds admitted by X.680 §46.3's ISO 8601 reference require typed runtime
	// support too; this scanner cannot admit a value the typed parser refuses.
	if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return false
	}
	if day > time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0, time.UTC).Day() {
		return false
	}
	if s.phase == 2 {
		if s.zoneCount != 4 && (utc || s.zoneCount != 2) {
			return false
		}
		if timeDigitPair(s.zone[0], s.zone[1]) > 23 {
			return false
		}
		if s.zoneCount == 4 && timeDigitPair(s.zone[2], s.zone[3]) > 59 {
			return false
		}
	}
	return true
}
