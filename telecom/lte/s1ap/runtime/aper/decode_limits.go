// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/decode_limits.go; SHA-256 23312b96381516ba0498a4e35724a91f6b0d4da27334bc389b063444d08c0250.
package aper

import "fmt"

// DecodeLimits bound one PER decode. Zero fields select defaults.
// X.691 (02/2021) §§11.2.1 and 11.9.3.8 define open types and fragmented
// lengths without operational ceilings; these are receiver limits, not wire
// restrictions. Positive values up to the host int limit are accepted.
type DecodeLimits struct {
	MaxDepth         int // nested generated values, including the root
	MaxElements      int // sum of all SEQUENCE OF and SET OF element counts
	MaxOpenTypeDepth int // nested decoded open types
	MaxWork          int // total bits examined, including nested rereads
}

// DefaultDecodeLimits bounds recursion, collection growth and repeated work
// on untrusted encodings. The 102 committed PER release vectors reached at
// most depth 13, 9 total elements, open-type depth 1 and 1016 bits of work;
// these defaults leave headroom above each observed maximum. Callers may
// raise individual fields for larger trusted profiles.
func DefaultDecodeLimits() DecodeLimits {
	return DecodeLimits{MaxDepth: 128, MaxElements: 100000, MaxOpenTypeDepth: 128, MaxWork: 64 << 20}
}

// DecodeUsage reports the high-water marks and totals of one decode. A caller
// may supply DecodeOptions.Usage to measure a decode; it must not share that
// pointer across concurrent decodes.
type DecodeUsage struct {
	MaxDepth         int
	Elements         uint64
	MaxOpenTypeDepth int
	Work             uint64
}

// DecodeBudget is the shared state of one PER decode. Generated entry points
// provide stack storage through NewDecodeBuffer, so accounting adds no common
// path allocations. Its zero value is ready for initialization; do not share
// it between independent or concurrent decodes.
type DecodeBudget struct {
	limits    DecodeLimits
	usage     DecodeUsage
	report    *DecodeUsage
	depth     int
	openDepth int
	err       error
}

func effectiveDecodeLimits(raw DecodeLimits) (DecodeLimits, error) {
	if raw.MaxDepth < 0 || raw.MaxElements < 0 || raw.MaxOpenTypeDepth < 0 || raw.MaxWork < 0 {
		return DecodeLimits{}, fmt.Errorf("%w: PER decode limits must be nonnegative (zero selects default)", ErrInvalidValue)
	}
	limits := DefaultDecodeLimits()
	if raw.MaxDepth != 0 {
		limits.MaxDepth = raw.MaxDepth
	}
	if raw.MaxElements != 0 {
		limits.MaxElements = raw.MaxElements
	}
	if raw.MaxOpenTypeDepth != 0 {
		limits.MaxOpenTypeDepth = raw.MaxOpenTypeDepth
	}
	if raw.MaxWork != 0 {
		limits.MaxWork = raw.MaxWork
	}
	return limits, nil
}

// ValidateDecodeOptions rejects malformed PER limits before reading input.
func ValidateDecodeOptions(options DecodeOptions) error {
	_, err := effectiveDecodeLimits(options.Limits)
	return err
}

func (budget *DecodeBudget) publish() {
	if budget.report != nil {
		*budget.report = budget.usage
	}
}

func (budget *DecodeBudget) fail(message string) error {
	if budget.err == nil {
		budget.err = fmt.Errorf("%w: %s", ErrResourceLimit, message)
	}
	return budget.err
}

// EnterDecodeValue accounts for one generated value before its decoder runs.
// Pair a successful call with LeaveDecodeValue, including on error paths.
func (bb *BitBuffer) EnterDecodeValue() error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if budget.depth >= budget.limits.MaxDepth {
		return budget.fail("PER nesting depth exceeded")
	}
	budget.depth++
	if budget.depth > budget.usage.MaxDepth {
		budget.usage.MaxDepth = budget.depth
		budget.publish()
	}
	return nil
}

// LeaveDecodeValue closes a generated value's nesting level.
func (bb *BitBuffer) LeaveDecodeValue() {
	budget := bb.decodeBudget()
	if budget.depth > 0 {
		budget.depth--
	}
}

// ChargeElements reserves a collection fragment before the generated decoder
// enters its element loop. The length determinant is governed by X.691
// (02/2021) §11.9.3.8; this check adds only a receiver resource ceiling.
func (bb *BitBuffer) ChargeElements(count int64) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if count < 0 {
		return fmt.Errorf("%w: negative collection element count", ErrInvalidValue)
	}
	if uint64(count) > uint64(budget.limits.MaxElements)-budget.usage.Elements {
		return budget.fail("PER collection element limit exceeded")
	}
	budget.usage.Elements += uint64(count)
	budget.publish()
	return nil
}

// EnterOpenType reserves the nesting level of an inherited child buffer.
// Pair a successful entry with LeaveOpenType, including on error paths.
func (bb *BitBuffer) EnterOpenType() error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if budget.openDepth >= budget.limits.MaxOpenTypeDepth {
		return budget.fail("PER open-type nesting depth exceeded")
	}
	budget.openDepth++
	if budget.openDepth > budget.usage.MaxOpenTypeDepth {
		budget.usage.MaxOpenTypeDepth = budget.openDepth
		budget.publish()
	}
	return nil
}

func (bb *BitBuffer) decodeBudget() *DecodeBudget {
	if bb.budget == nil {
		bb.budget = &DecodeBudget{limits: DefaultDecodeLimits()}
	}
	return bb.budget
}

// LeaveOpenType closes the nesting level opened by EnterOpenType.
func (bb *BitBuffer) LeaveOpenType() {
	if bb.budget.openDepth > 0 {
		bb.budget.openDepth--
	}
}

func (bb *BitBuffer) InheritOpenTypeDecodeOptions(parent *BitBuffer) error {
	bb.InheritDecodeOptions(parent)
	return bb.EnterOpenType()
}

func (bb *BitBuffer) Usage() DecodeUsage { return bb.decodeBudget().usage }
