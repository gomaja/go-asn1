// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/decode_limits.go; SHA-256 cb8e23b9c9785ddf036743271e589ac12ec2ca4c291f973d4977ed1832421a5b.
package aper

import "fmt"

// decodeLimits is private instrumentation for the retained recovery/refusal
// harness. Complete source codecs always use Limits and DefaultLimits.
type decodeLimits struct {
	MaxDepth         int // nested generated values, including the root
	MaxElements      int // sum of all SEQUENCE OF and SET OF element counts
	MaxOpenTypeDepth int // nested decoded open types
	MaxWork          int // total bits examined, including nested rereads
}

// defaultLegacyLimits preserves the private recovery harness accounting.
func defaultLegacyLimits() decodeLimits {
	return decodeLimits{MaxDepth: 128, MaxElements: 100000, MaxOpenTypeDepth: 128, MaxWork: 64 << 20}
}

// DecodeUsage is a copy of one operation's high-water marks and totals.
// DecodeState.Usage and BitBuffer.Usage never expose mutable counters.
type DecodeUsage struct {
	MaxDepth         int
	Elements         uint64
	MaxOpenTypeDepth int
	Work             uint64
	AllocatedBytes   uint64
	Fragments        uint64
	Reports          uint64
}

// DecodeBudget is the shared state of one PER decode. Generated entry points
// provide stack storage through NewDecodeBuffer, so accounting adds no common
// path allocations. Its zero value is ready for initialization; do not share
// it between independent or concurrent decodes.
type DecodeBudget struct {
	callReport                    *DecodeReport
	operational                   Limits
	allocated, fragments, reports uint64
	outputLimited                 bool
	reading                       bool
	locating                      bool
	limits                        decodeLimits
	usage                         DecodeUsage
	report                        *DecodeUsage
	depth                         int
	openDepth                     int
	err                           error
	// Origin maps are allocated on demand. Keeping the maps behind a pointer
	// preserves DecodeBudget's value comparability for existing callers.
	origin     *originMap
	owner      *semanticArena
	encodePlan *ReplayPlan
}

type originMap struct {
	readers      map[*BitBuffer]*fragmentedReader
	dataBases    map[*byte]uint64
	dataSegments map[*byte][]wireSegment
	bases        map[*BitBuffer]uint64
	segments     map[*BitBuffer][]wireSegment
}

func effectiveDecodeLimits(raw decodeLimits) (decodeLimits, error) {
	if raw.MaxDepth < 0 || raw.MaxElements < 0 || raw.MaxOpenTypeDepth < 0 || raw.MaxWork < 0 {
		return decodeLimits{}, fmt.Errorf("%w: PER decode limits must be nonnegative (zero selects default)", ErrInvalidValue)
	}
	limits := defaultLegacyLimits()
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

// validateDecodeSettings rejects malformed PER limits before reading input.
func validateDecodeSettings(options decodeSettings) error {
	_, err := effectiveDecodeLimits(options.Limits)
	return err
}

func (budget *DecodeBudget) publish() {
	if budget.report != nil {
		*budget.report = budget.usage
	}
}

// EnterDecodeValue accounts for one generated value before its decoder runs.
// Pair a successful call with LeaveDecodeValue, including on error paths.
func (bb *BitBuffer) EnterDecodeValue() error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if budget.depth >= budget.limits.MaxDepth {
		return bb.resourceError("PER nesting depth exceeded")
	}
	if budget.operational != (Limits{}) {
		if err := bb.ChargeWork(1); err != nil {
			return err
		}
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
		return bb.resourceError("PER collection element limit exceeded")
	}
	if budget.operational != (Limits{}) {
		if err := bb.ChargeWork(uint64(count)); err != nil {
			return err
		}
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
		return bb.resourceError("PER open-type nesting depth exceeded")
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
		bb.budget = &DecodeBudget{limits: defaultLegacyLimits()}
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

func (bb *BitBuffer) Usage() DecodeUsage {
	budget := bb.decodeBudget()
	usage := budget.usage
	usage.AllocatedBytes = budget.allocated
	usage.Fragments = budget.fragments
	usage.Reports = budget.reports
	return usage
}
