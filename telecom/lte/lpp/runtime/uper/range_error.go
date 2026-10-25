// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/range_error.go; SHA-256 eb223985bc951962539c629c29ccd04e34b41143be66ec29aacf9eba876fc544.
package uper

import (
	"fmt"
	"math/big"
)

// constrainedOffsetError reports a decoded constrained whole number outside
// its range. ITU-T X.691 (02/2021) 11.5 encodes the offset n - lb, so a
// field can carry an offset beyond ub - lb. The error states the rejected
// value lb + offset in the same domain as the bounds, then the offset as it
// appeared on the wire. The value is computed exactly, so it cannot wrap.
func constrainedOffsetError(lower, offset, upper *big.Int) error {
	value := new(big.Int).Add(lower, offset)
	return fmt.Errorf("%w: value %s (offset %s) exceeds range [%s..%s]", ErrInvalidValue, value, offset, lower, upper)
}

func int64OffsetError(offset uint64, lb, ub int64) error {
	return constrainedOffsetError(big.NewInt(lb), new(big.Int).SetUint64(offset), big.NewInt(ub))
}
