package ber

// UnusedBitCount converts a well-shaped abstract BIT STRING length to the
// contents octet required by X.690 (02/2021) §8.6.2.2. Generated encoders
// validate the shape before calling this helper.
func UnusedBitCount(bitLength int) int {
	return (8 - bitLength%8) % 8
}
