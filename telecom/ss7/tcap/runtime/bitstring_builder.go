// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/bitstring_builder.go; SHA-256 1531e77023ccabac302dbfa2d73a17649a77ca5bdf87f3631df526b4cda73f1e.
package runtime

import (
	"fmt"
)

// The builder ceiling bounds fresh in-memory allocation. Wire decoding has
// its own budgets. Mutations within existing, valid storage do not allocate.
const bitStringBuilderMaxBytes = 16 << 20

// NewBitString constructs exactly bitLength bits, with the selected positions
// set. Position zero is the leading bit (ITU-T X.690 (02/2021) §8.6.2.1).
// Negative lengths, positions outside the value, and storage beyond 16 MiB
// are errors. The length is not padded or inferred from the selected bits.
func NewBitString(bitLength int, set ...int) (BitString, error) {
	if bitLength < 0 || bitLength > bitStringBuilderMaxBytes*8 {
		return BitString{}, fmt.Errorf("BIT STRING length exceeds builder limits")
	}
	// Validate positions before allocating even when the requested length fits.
	for _, bit := range set {
		if bit < 0 || bit >= bitLength {
			return BitString{}, fmt.Errorf("BIT STRING position %d outside length %d", bit, bitLength)
		}
	}
	if bitLength == 0 {
		return BitString{}, nil
	}
	value := BitString{Bytes: make([]byte, bitStringBuilderOctets(bitLength)), BitLength: bitLength}
	for _, bit := range set {
		value.Bytes[bit/8] |= 0x80 >> uint(bit%8)
	}
	return value, nil
}

// bitStringBuilderOctets avoids overflowing bitLength+7. Its caller first
// rejects negative lengths; division and the one-octet remainder fit int.
func bitStringBuilderOctets(bitLength int) int {
	octets := bitLength / 8
	if bitLength%8 != 0 {
		octets++
	}
	return octets
}

func validateBitStringBuilder(value *BitString) error {
	if value == nil {
		return fmt.Errorf("nil BIT STRING receiver")
	}
	if value.BitLength < 0 || len(value.Bytes) != bitStringBuilderOctets(value.BitLength) {
		return fmt.Errorf("BIT STRING length and storage disagree")
	}
	return nil
}

// Set sets a position, growing the logical value and zero-filling new bits.
// Growth is limited to 16 MiB. Existing length/storage must agree before any
// mutation. Unused tail bits are cleared, including before growth can expose
// them as logical bits (X.690 (02/2021) §§8.6.2.1-8.6.2.2).
func (value *BitString) Set(bit int) error {
	if err := validateBitStringBuilder(value); err != nil {
		return err
	}
	if bit < 0 {
		return fmt.Errorf("negative BIT STRING position")
	}
	length := value.BitLength
	if bit >= length {
		// Check before adding one: MaxInt is an invalid growth request too.
		if bit >= bitStringBuilderMaxBytes*8 {
			return fmt.Errorf("BIT STRING growth exceeds builder limits")
		}
		length = bit + 1
	}
	storage := value.Bytes
	octets := bitStringBuilderOctets(length)
	if octets > len(storage) {
		storage = make([]byte, octets)
		copy(storage, value.Bytes)
	}
	// Dirty unused bits are outside the old abstract value, so they must never
	// become set logical bits when the value grows within its final octet.
	if remainder := value.BitLength % 8; remainder != 0 {
		storage[len(value.Bytes)-1] &= 0xff << uint(8-remainder)
	}
	storage[bit/8] |= 0x80 >> uint(bit%8)
	if remainder := length % 8; remainder != 0 {
		storage[len(storage)-1] &= 0xff << uint(8-remainder)
	}
	value.Bytes, value.BitLength = storage, length
	return nil
}

// Clear clears a position without changing the logical length. Beyond-length
// positions leave all logical bits unchanged. Every successful call clears
// unused tail bits; a negative position or invalid storage leaves the value
// unchanged. X.690 (02/2021) §§8.6.2.1-8.6.2.2 distinguish value and unused bits.
func (value *BitString) Clear(bit int) error {
	if err := validateBitStringBuilder(value); err != nil {
		return err
	}
	if bit < 0 {
		return fmt.Errorf("negative BIT STRING position")
	}
	if bit < value.BitLength {
		value.Bytes[bit/8] &^= 0x80 >> uint(bit%8)
	}
	if remainder := value.BitLength % 8; remainder != 0 {
		value.Bytes[len(value.Bytes)-1] &= 0xff << uint(8-remainder)
	}
	return nil
}
