// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/limits.go; SHA-256 e0efd5be8908d2a5190d0a63aca6c4e454b445033d6098a1a8f235e24ea99653.
package aper

import (
	"fmt"
	"math"
)

// Limits are operational ceilings, independent of ASN.1 constraints. Zero
// fields select DefaultLimits. One work unit is one examined bit or one
// requested or copied octet; visited values, collection elements, fragment
// determinants and report records also cost one unit. Each complete operation
// first reserves 1,024 bytes/units for fixed call and diagnostic state. Map
// entries and validation records reserve documented conservative metadata space.
// Integer arithmetic reserves eight linear workspaces, each with 96 bytes of
// header/carry headroom; bounded scalar encoders reserve their small scratch.
// A nested known open value shares all counters with its enclosing operation.
type Limits struct {
	MaxOutputBytes    uint64
	MaxInputBytes     uint64
	MaxOpenTypeBytes  uint64
	MaxDepth          uint64
	MaxElements       uint64
	MaxFragments      uint64
	MaxWork           uint64
	MaxAllocatedBytes uint64
	MaxReports        uint64
}

// DefaultLimits supplies finite operational defaults; they are not source limits.
func DefaultLimits() Limits {
	return Limits{MaxOutputBytes: 16 << 20, MaxInputBytes: 16 << 20, MaxOpenTypeBytes: 16 << 20, MaxDepth: 64, MaxElements: 1 << 20, MaxFragments: 4096, MaxWork: 32 << 20, MaxAllocatedBytes: 128 << 20, MaxReports: 1024}
}

func effectiveLimits(raw Limits) (Limits, error) {
	result := DefaultLimits()
	fields := []struct {
		raw uint64
		dst *uint64
	}{
		{raw.MaxOutputBytes, &result.MaxOutputBytes}, {raw.MaxInputBytes, &result.MaxInputBytes}, {raw.MaxOpenTypeBytes, &result.MaxOpenTypeBytes},
		{raw.MaxDepth, &result.MaxDepth}, {raw.MaxElements, &result.MaxElements},
		{raw.MaxFragments, &result.MaxFragments}, {raw.MaxWork, &result.MaxWork},
		{raw.MaxAllocatedBytes, &result.MaxAllocatedBytes}, {raw.MaxReports, &result.MaxReports},
	}
	for _, field := range fields {
		if field.raw > uint64(math.MaxInt) {
			return Limits{}, fmt.Errorf("%w: limit exceeds host int", ErrInvalidOptions)
		}
		if field.raw != 0 {
			*field.dst = field.raw
		}
	}
	if result.MaxOutputBytes > uint64(math.MaxInt/8) || result.MaxInputBytes > uint64(math.MaxInt/8) || result.MaxOpenTypeBytes > uint64(math.MaxInt/8) {
		return Limits{}, fmt.Errorf("%w: byte limit exceeds representable bit length", ErrInvalidOptions)
	}
	return result, nil
}
