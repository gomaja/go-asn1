package ber

import "fmt"

// ValidateBitStringLength checks that the supplied storage represents exactly
// the stated abstract bit length (ITU-T X.690 (02/2021) §8.6.2.2).
func ValidateBitStringLength(bytes []byte, bitLength int) error {
	if bitLength < 0 {
		return fmt.Errorf("%w: negative bit string length %d", ErrInvalidValue, bitLength)
	}
	want := bitLength / 8
	if bitLength%8 != 0 {
		want++
	}
	if len(bytes) != want {
		return fmt.Errorf("%w: BIT STRING length %d disagrees with %d content octets", ErrInvalidValue, bitLength, len(bytes))
	}
	return nil
}

// ValidateDERBitString applies the zero-padding rule of ITU-T X.690
// (02/2021) §11.2.1 to an abstract BIT STRING.
func ValidateDERBitString(bytes []byte, bitLength int) error {
	if err := ValidateBitStringLength(bytes, bitLength); err != nil {
		return err
	}
	if rem := bitLength % 8; rem != 0 && bytes[len(bytes)-1]&byte((1<<(8-rem))-1) != 0 {
		return fmt.Errorf("%w: DER BIT STRING has nonzero unused bits", ErrInvalidValue)
	}
	return nil
}
