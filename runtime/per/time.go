package per

import (
	"fmt"
	"time"
)

// X.691 (02/2021) 10.6.5 encodes UTCTime as its VisibleString
// definition in X.680 (02/2021) 47.3, subject to the canonical
// X.690 (02/2021) 11.8.1-11.8.2 Z and seconds requirements.
func EncodeUTCTime(bb *BitBuffer, value time.Time) error {
	text, err := canonicalUTCTime(value)
	if err != nil {
		return err
	}
	return EncodeKnownMultiplierString(bb, text, 7, 0, 0, false)
}

func DecodeUTCTime(bb *BitBuffer) (time.Time, error) {
	text, err := DecodeKnownMultiplierString(bb, 7, 0, 0, false)
	if err != nil {
		return time.Time{}, err
	}
	return parseCanonicalUTCTime(text)
}

// In aligned PER, X.691 (02/2021) 30.4 encodes this VisibleString
// with octet-aligned character units, as checked against pycrate 0.7.11.
func EncodeUTCTimeAligned(bb *BitBuffer, value time.Time) error {
	text, err := canonicalUTCTime(value)
	if err != nil {
		return err
	}
	return EncodeOctetStringAligned(bb, []byte(text), 0, 0, false)
}

func DecodeUTCTimeAligned(bb *BitBuffer) (time.Time, error) {
	data, err := DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return time.Time{}, err
	}
	return parseCanonicalUTCTime(string(data))
}

func canonicalUTCTime(value time.Time) (string, error) {
	utc := value.UTC()
	if utc.Year() < 1950 || utc.Year() > 2049 || utc.Nanosecond() != 0 {
		return "", fmt.Errorf("%w: UTCTime cannot represent %s", ErrConstraintViolation, value)
	}
	return utc.Format("060102150405Z"), nil
}

func parseCanonicalUTCTime(text string) (time.Time, error) {
	if len(text) != 13 || text[12] != 'Z' {
		return time.Time{}, fmt.Errorf("%w: noncanonical UTCTime %q", ErrInvalidValue, text)
	}
	for index := 0; index < 12; index++ {
		if text[index] < '0' || text[index] > '9' {
			return time.Time{}, fmt.Errorf("%w: noncanonical UTCTime %q", ErrInvalidValue, text)
		}
	}
	value, err := time.Parse("060102150405Z", text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: UTCTime %q: %v", ErrInvalidValue, text, err)
	}
	// Go uses a 69-year pivot; X.680 UTCTime uses the 1950/2049 window.
	if value.Year() >= 2050 && value.Year() <= 2068 {
		value = value.AddDate(-100, 0, 0)
	}
	if value.Format("060102150405Z") != text {
		return time.Time{}, fmt.Errorf("%w: noncanonical UTCTime %q", ErrInvalidValue, text)
	}
	return value, nil
}
