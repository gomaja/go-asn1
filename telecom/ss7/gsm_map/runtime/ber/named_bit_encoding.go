// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/named_bit_encoding.go; SHA-256 bf71d2f77b165ac3693d8d8fc6a0f2fac2f2c929a6b8cba70a84ec30d84e1e4c.
package ber

import (
	"fmt"
	"math/bits"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// namedBitEncodingLength returns the smallest member of the intersection of
// source SIZE sets at or above significant. Each set is a union of intervals.
// X.680 (02/2021) §22.7; X.690 (02/2021) §§8.6.2.4, 11.2.2.
func namedBitEncodingLength(significant int, sets []NamedBitSizeSet) (int, error) {
	if significant < 0 {
		return 0, fmt.Errorf("%w: negative named BIT STRING significant length", ErrInvalidValue)
	}
	// Validate every interval before selecting, including intervals after a match.
	for _, set := range sets {
		for _, interval := range set {
			if interval.Min < 0 || interval.Max < -1 || interval.Max >= 0 && interval.Max < interval.Min {
				return 0, fmt.Errorf("%w: invalid named BIT STRING SIZE interval", ErrInvalidValue)
			}
		}
	}
	candidate := significant
	for {
		next := candidate
		for _, set := range sets {
			above, foundAbove, matched := 0, false, false
			for _, interval := range set {
				if candidate >= interval.Min && (interval.Max < 0 || candidate <= interval.Max) {
					matched = true
					break
				}
				if interval.Min > candidate && (!foundAbove || interval.Min < above) {
					above, foundAbove = interval.Min, true
				}
			}
			if !matched {
				if !foundAbove {
					return 0, &namedBitSizeError{significant: significant}
				}
				if above > next {
					next = above
				}
			}
		}
		if next == candidate {
			return candidate, nil
		}
		candidate = next
	}
}

// NormalizeNamedBitStringForEncoding returns an owned representation with the
// smallest source-permitted length equivalent by trailing zero bits. DER callers
// then remove trailing zero bits with EncodeDERNamedBitString. Unnamed BIT STRINGs
// must retain their exact length and must not call this helper. Caller storage
// and replay state are unchanged. X.680 (02/2021) §22.7; X.690 (02/2021)
// §§8.6.2.2–8.6.2.4, 11.2.1–11.2.2.
func NormalizeNamedBitStringForEncoding(value runtime.BitString, sets []NamedBitSizeSet) (runtime.BitString, error) {
	if err := ValidateBitStringLength(value.Bytes, value.BitLength); err != nil {
		return runtime.BitString{}, err
	}
	significant := 0
	for index := len(value.Bytes); index > 0; {
		index--
		octet := value.Bytes[index]
		if index == len(value.Bytes)-1 && value.BitLength%8 != 0 {
			octet &= 0xff << uint(8-value.BitLength%8)
		}
		if octet != 0 {
			significant = index*8 + (8 - bits.TrailingZeros8(octet))
			break
		}
	}
	length, err := namedBitEncodingLength(significant, sets)
	if err != nil {
		return runtime.BitString{}, err
	}
	// Normalization does not inherit the builder's 16 MiB allocation ceiling.
	// Division avoids overflow at the host-int limit.
	octets := length / 8
	if length%8 != 0 {
		octets++
	}
	result := runtime.BitString{Bytes: make([]byte, octets), BitLength: length}
	copy(result.Bytes, value.Bytes)
	// Unused input bits are padding, including when SIZE requires extending the
	// logical value within its last octet or into subsequent octets.
	if n := value.BitLength % 8; n != 0 && value.BitLength/8 < len(result.Bytes) {
		result.Bytes[value.BitLength/8] &= 0xff << uint(8-n)
	}
	if n := length % 8; n != 0 {
		result.Bytes[len(result.Bytes)-1] &= 0xff << uint(8-n)
	}
	return result, nil
}

// NewNamedBitString constructs named bits using the complete source SIZE
// intersection. Numeric positions need not appear in the NamedBitList
// (X.680 (02/2021) §22.6). The runtime builder's allocation ceiling applies.
// X.680 (02/2021) §22.7; X.690 (02/2021) §8.6.2.4.
func NewNamedBitString(sets []NamedBitSizeSet, set ...int) (runtime.BitString, error) {
	significant := 0
	for _, bit := range set {
		// Check before bit+1, including the host-int maximum.
		if bit < 0 || bit >= (16<<20)*8 {
			return runtime.BitString{}, fmt.Errorf("%w: named BIT STRING position exceeds builder limits", ErrInvalidValue)
		}
		if bit >= significant {
			significant = bit + 1
		}
	}
	length, err := namedBitEncodingLength(significant, sets)
	if err != nil {
		return runtime.BitString{}, err
	}
	return runtime.NewBitString(length, set...)
}

// NormalizeNamedBitStringForBEREncoding applies the source length normalization
// without bypassing explicit tolerance for a representable SIZE violation.
// If no permitted equivalent exists, tolerant BER retains an owned value at its
// original logical length; the generated source SIZE checks still report it.
// Invalid storage, source intervals and options always fail. DER uses the strict
// NormalizeNamedBitStringForEncoding path. X.680 (02/2021) §§22.7, 51.5;
// X.690 (02/2021) §§8.6.2.2–8.6.2.4, 11.2.2.
func NormalizeNamedBitStringForBEREncoding(value runtime.BitString, sets []NamedBitSizeSet, options ...EncodeOption) (runtime.BitString, error) {
	config, optionErr := encodeOptions(options)
	if optionErr != nil {
		return runtime.BitString{}, optionErr
	}
	normalized, err := NormalizeNamedBitStringForEncoding(value, sets)
	if err == nil {
		return normalized, nil
	}
	if _, sizeFailure := err.(*namedBitSizeError); !sizeFailure || !config.tolerant {
		return runtime.BitString{}, err
	}
	// A fixed copy length preserves the caller's observed SIZE and clears unused
	// storage bits through the same owned normalization mechanics.
	return NormalizeNamedBitStringForEncoding(value, []NamedBitSizeSet{{{Min: value.BitLength, Max: value.BitLength}}})
}

type namedBitSizeError struct{ significant int }

func (err *namedBitSizeError) Error() string {
	return fmt.Sprintf("%v: named BIT STRING significant length %d has no permitted SIZE", ErrInvalidValue, err.significant)
}
func (*namedBitSizeError) Unwrap() error { return ErrInvalidValue }
