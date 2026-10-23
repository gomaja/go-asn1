// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/range_error.go; SHA-256 523621dd4e073c2d605c8e2580f68ad1e689569d16d77ac2c0ec12d30055981f.
package aper

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

// uint64OffsetError reports an invalid unsigned constrained offset exactly.
func uint64OffsetError(offset, lower, upper uint64) error {
	return constrainedOffsetError(new(big.Int).SetUint64(lower), new(big.Int).SetUint64(offset), new(big.Int).SetUint64(upper))
}
