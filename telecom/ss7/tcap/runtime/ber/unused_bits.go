// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/unused_bits.go; SHA-256 1bc247977170dc362a5f5300cfae54a9a6362b561fabab065938299bb7d593dd.
package ber

// UnusedBitCount converts a well-shaped abstract BIT STRING length to the
// contents octet required by X.690 (02/2021) §8.6.2.2. Generated encoders
// validate the shape before calling this helper.
func UnusedBitCount(bitLength int) int {
	return (8 - bitLength%8) % 8
}
