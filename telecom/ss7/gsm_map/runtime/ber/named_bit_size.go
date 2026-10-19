// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/named_bit_size.go; SHA-256 59a54170b1eb059f8dd824fe62c4c8db749603dd3a09e43c090a310085c18aaf.
package ber

import (
	"math/bits"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// NamedBitSizeRange is an inclusive SIZE interval. Max=-1 means unbounded.
type NamedBitSizeRange struct{ Min, Max int }

// NamedBitSizeSet is one SIZE constraint's permitted intervals.
type NamedBitSizeSet []NamedBitSizeRange

// NormalizeNamedBitStringSize chooses the shortest permitted abstract value
// that differs from the received value only by added or removed trailing zero bits.
// A failed intersection leaves the value for the generated constraint checks.
// ITU-T X.680 (02/2021) §22.7; X.690 (02/2021) §§8.6.2.4, 11.2.2 NOTE 1.
func NormalizeNamedBitStringSize(value runtime.BitString, sets []NamedBitSizeSet, options ...DecodeOption) runtime.BitString {
	if value.BitLength < 0 || len(sets) == 0 {
		return value
	}
	// Leave malformed shapes to the generated structural checks. Unused
	// wire padding cannot become a set abstract bit during normalization.
	width := value.BitLength / 8
	if value.BitLength%8 != 0 {
		width++
	}
	if len(value.Bytes) != width {
		return value
	}
	candidate := 0
	for index := len(value.Bytes); index > 0; {
		index--
		octet := value.Bytes[index]
		if index == len(value.Bytes)-1 && value.BitLength%8 != 0 {
			octet &= byte(0xff << (8 - value.BitLength%8))
		}
		if octet != 0 {
			// index is bounded by ceil(BitLength/8), so this bit index
			// fits int even at the public representation's limit.
			candidate = index*8 + (8 - bits.TrailingZeros8(octet))
			break
		}
	}
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
	// Keep the received form for BER replay when the abstract value
	// needs zero extension or trimming to meet the permitted intersection.
	MarkBERNonCanonical(options)
	width = candidate / 8
	if candidate%8 != 0 {
		width++
	}
	bytes := make([]byte, width)
	copy(bytes, value.Bytes)
	// X.690 (02/2021) §8.6.2.2: unused bits in the final received
	// octet are padding, not value bits when §22.7 permits extension.
	if n := value.BitLength % 8; n != 0 && value.BitLength/8 < len(bytes) {
		bytes[value.BitLength/8] &= byte(0xff << (8 - n))
	}
	return runtime.BitString{Bytes: bytes, BitLength: candidate}
}
