// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/options.go; SHA-256 d89688cbf8c9ec4eed7f1dbd48e32f523c14eb89a72e5cbcfb601d8899a5d082.
package aper

import (
	"strconv"
)

// ContainedDecoding preserves the option values accepted by the published
// API. APER entry points require Eager and reject the other values.
type ContainedDecoding uint8

const (
	Eager ContainedDecoding = iota
	DeferOnError
	DeferAll
)

// String returns Eager, DeferOnError or DeferAll for a known policy.
// Unknown values are formatted as ContainedDecoding(n).
func (mode ContainedDecoding) String() string {
	switch mode {
	case Eager:
		return "Eager"
	case DeferOnError:
		return "DeferOnError"
	case DeferAll:
		return "DeferAll"
	default:
		return "ContainedDecoding(" + strconv.Itoa(int(mode)) + ")"
	}
}

// DeferralLog is the option carrier for unsupported contained-value policies.
// APER entry points reject these policies before reading input.
type DeferralLog struct{}
