// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/options.go; SHA-256 43871a87b1eaff6696ef0e0ca711b0298e24562b9cbb653d13ab840f18f94649.
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
