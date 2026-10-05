package ber

import "github.com/gomaja/go-asn1/runtime"

// NamedBitSizeRange is an inclusive SIZE interval. Max=-1 means unbounded.
type NamedBitSizeRange struct{ Min, Max int }

// NamedBitSizeSet is one SIZE constraint's permitted intervals.
type NamedBitSizeSet []NamedBitSizeRange

// NormalizeNamedBitStringSize chooses the shortest permitted abstract value
// that differs from the received value only by added trailing zero bits.
// A failed intersection leaves the value for the generated constraint checks.
// ITU-T X.680 (02/2021) §22.7; X.690 (02/2021) §§8.6.2.4, 11.2.2 NOTE 1.
func NormalizeNamedBitStringSize(value runtime.BitString, sets []NamedBitSizeSet, options ...DecodeOption) runtime.BitString {
	if value.BitLength < 0 || len(sets) == 0 {
		return value
	}
	candidate := value.BitLength
	for {
		next := candidate
		for _, set := range sets {
			matched := false
			above := int(^uint(0) >> 1)
			for _, interval := range set {
				if candidate >= interval.Min && (interval.Max < 0 || candidate <= interval.Max) {
					matched = true
					break
				}
				if interval.Min > candidate && interval.Min < above {
					above = interval.Min
				}
			}
			if !matched {
				if above == int(^uint(0)>>1) {
					return value
				}
				if above > next {
					next = above
				}
			}
		}
		if next == candidate {
			break
		}
		candidate = next
	}
	if candidate == value.BitLength {
		return value
	}
	// Keep an encoded short form for BER replay when its decoded abstract
	// value needs zero extension to meet SIZE.
	MarkBERNonCanonical(options)
	width := candidate / 8
	if candidate%8 != 0 {
		width++
	}
	bytes := make([]byte, width)
	copy(bytes, value.Bytes)
	// X.690 (02/2021) §8.6.2.2: unused bits in the final received
	// octet are padding, not value bits when §22.7 permits extension.
	if n := value.BitLength % 8; n != 0 {
		bytes[value.BitLength/8] &= byte(0xff << (8 - n))
	}
	return runtime.BitString{Bytes: bytes, BitLength: candidate}
}
