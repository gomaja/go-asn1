package ber

import (
	"fmt"
	"math"
)

// BitStringBitLength converts X.690 (02/2021) §8.6's octets and unused-bit
// count into the host-int length carried by runtime.BitString.
func BitStringBitLength(octets, unused int) (int, error) {
	if octets < 0 || unused < 0 || unused > 7 || octets == 0 && unused != 0 {
		return 0, fmt.Errorf("%w: invalid BIT STRING length", ErrInvalidValue)
	}
	if octets == 0 {
		return 0, nil
	}
	lastOctetBits := 8 - unused
	if octets-1 > (math.MaxInt-lastOctetBits)/8 {
		return 0, fmt.Errorf("%w: BIT STRING length exceeds host int", ErrInvalidValue)
	}
	return (octets-1)*8 + lastOctetBits, nil
}
