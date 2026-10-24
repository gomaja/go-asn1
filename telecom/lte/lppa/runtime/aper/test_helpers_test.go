// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/test_helpers_test.go; SHA-256 ec07375a689daf416f2c865d1ddb0bebc6b330ed4893d13af186e6fb40dafb6d.
package aper

import "math/big"

// These adapters direct the original integer guards through the bounds API
// that LPPa's generated code uses.
func testBigBound(value *int64) *big.Int {
	if value == nil {
		return nil
	}
	return big.NewInt(*value)
}
func encodeIntegerBigForTest(bb *BitBuffer, value *big.Int, lower, upper *int64, extensible bool) error {
	return EncodeIntegerBigBoundsAligned(bb, value, testBigBound(lower), testBigBound(upper), extensible)
}
func decodeIntegerBigForTest(bb *BitBuffer, lower, upper *int64, extensible bool) (*big.Int, error) {
	return DecodeIntegerBigBoundsAligned(bb, testBigBound(lower), testBigBound(upper), extensible)
}
func equalSignificantBits(left, right []byte, length int) bool {
	for bit := 0; bit < length; bit++ {
		if left[bit/8]&(0x80>>uint(bit%8)) != right[bit/8]&(0x80>>uint(bit%8)) {
			return false
		}
	}
	return true
}
