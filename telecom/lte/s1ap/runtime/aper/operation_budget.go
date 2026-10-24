// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/operation_budget.go; SHA-256 fb3e16719b5a8b5751235a90a9e56b08f08edb97baab5dc49189bfffa48524bd.
package aper

import (
	"fmt"
	"math"
)

// operationMetadataBytes reserves fixed call state, cursors and diagnostic
// envelope storage. Variable backing arrays and copies are charged separately.
const operationMetadataBytes uint64 = 1024

// NewOperationBudget starts one encode, build or validation operation. Nested
// values use this same budget; counters are never refunded on failure.
func NewOperationBudget(limits Limits) (*DecodeBudget, error) {
	budget := new(DecodeBudget)
	if err := initializeOperationBudget(budget, limits); err != nil {
		return nil, err
	}
	return budget, nil
}
func initializeOperationBudget(budget *DecodeBudget, limits Limits) error {
	effective, err := effectiveLimits(limits)
	if err != nil {
		return err
	}
	if effective.MaxAllocatedBytes < operationMetadataBytes || effective.MaxWork < operationMetadataBytes {
		return &DecodeError{Kind: Limit, Err: ErrResourceLimit}
	}
	*budget = DecodeBudget{allocated: operationMetadataBytes, usage: DecodeUsage{Work: operationMetadataBytes}, operational: effective, limits: decodeLimits{MaxDepth: int(effective.MaxDepth), MaxElements: int(effective.MaxElements), MaxOpenTypeDepth: int(effective.MaxDepth), MaxWork: int(effective.MaxWork)}, outputLimited: true}
	return nil
}

// EncodeBudget creates call-owned accounting from immutable options.
func EncodeBudget(options ...EncodeOption) (*DecodeBudget, error) {
	var limits Limits
	for _, option := range options {
		if option.hasLimits {
			limits = option.limits
		}
	}
	return NewOperationBudget(limits)
}

// BuildBudget creates call-owned accounting from immutable options.
func BuildBudget(options ...BuildOption) (*DecodeBudget, error) {
	var limits Limits
	for _, option := range options {
		if option.hasLimits {
			limits = option.limits
		}
	}
	return NewOperationBudget(limits)
}

// ValidationBudget creates call-owned accounting from immutable options.
func ValidationBudget(options ...ValidationOption) (*DecodeBudget, error) {
	var limits Limits
	for _, option := range options {
		if option.hasLimits {
			limits = option.limits
		}
	}
	limits.MaxOutputBytes = 0
	budget, err := NewOperationBudget(limits)
	if err == nil {
		budget.outputLimited = false
	}
	return budget, err
}

func (bb *BitBuffer) resourceError(message string) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	location := Location{}
	budget.locating = true
	reader := bb
	// Snapshot copies share the decode budget but have no cursor. Locate
	// their failure at the complete root reader's consumed boundary.
	if budget.reading && !reader.sourceReader && budget.owner != nil && budget.owner.nextBuffer > 0 {
		reader = &budget.owner.buffers[0]
	}
	if budget.reading && reader.BitPos() >= 0 {
		location.Spans, location.HasWireLocation = originalRange(reader, uint64(reader.BitPos()), uint64(reader.BitPos()))
	}
	budget.locating = false
	budget.err = &DecodeError{Kind: Limit, Location: location, Err: fmt.Errorf("%w: %s", ErrResourceLimit, message)}
	return budget.err
}

// ChargeAllocation reserves requested storage and copy work before allocation.
// Product is checked before multiplication; a unit is one requested octet.
func (bb *BitBuffer) ChargeAllocation(count, size uint64) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if size != 0 && count > uint64(math.MaxInt)/size {
		return bb.resourceError("allocation product overflows host int")
	}
	bytes := count * size
	if budget.operational.MaxAllocatedBytes != 0 {
		if bytes > budget.operational.MaxAllocatedBytes-budget.allocated {
			return bb.resourceError("allocated bytes exceeded")
		}
		if err := bb.ChargeWork(bytes); err != nil {
			return err
		}
		budget.allocated += bytes
	}
	return nil
}

// ChargeWork charges examined/emitted bits, copied octets, visited nodes and
// report records to the same aggregate ceiling, including abandoned paths.
func (bb *BitBuffer) ChargeWork(units uint64) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if units > uint64(budget.limits.MaxWork)-budget.usage.Work {
		return bb.resourceError("total work exceeded")
	}
	budget.usage.Work += units
	budget.publish()
	return nil
}

// chargeWork lets semantic visitors share the operation without a reader or
// writer wrapper. Only a failure needs the diagnostic buffer.
func (budget *DecodeBudget) chargeWork(units uint64) error {
	if budget.err != nil || units > uint64(budget.limits.MaxWork)-budget.usage.Work {
		return budget.workFailure()
	}
	budget.usage.Work += units
	budget.publish()
	return nil
}

func (budget *DecodeBudget) workFailure() error {
	if budget.err != nil {
		return budget.err
	}
	return NewBudgetBuffer(budget).resourceError("total work exceeded")
}

// ChargeFragment charges each determinant, including the terminating fragment.
func (bb *BitBuffer) ChargeFragment() error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if budget.operational.MaxFragments != 0 && budget.fragments >= budget.operational.MaxFragments {
		return bb.resourceError("fragments exceeded")
	}
	if err := bb.ChargeWork(1); err != nil {
		return err
	}
	budget.fragments++
	return nil
}

// ChargeReport reserves one report and its requested storage before publication.
func (bb *BitBuffer) ChargeReport(location Location, bytes uint64) error {
	budget := bb.decodeBudget()
	maximum := uint64(1024)
	if budget.operational.MaxReports != 0 {
		maximum = budget.operational.MaxReports
	}
	if budget.reports >= maximum {
		err := bb.resourceError("reports exceeded")
		if e, ok := err.(*DecodeError); ok {
			e.Location = location
		}
		return err
	}
	if err := bb.ChargeAllocation(1, bytes); err != nil {
		return err
	}
	if err := bb.ChargeWork(1); err != nil {
		return err
	}
	budget.reports++
	return nil
}

// Budget shares this operation with a generated known value or replay snapshot.
func (bb *BitBuffer) Budget() *DecodeBudget { return bb.decodeBudget() }

// NewBudgetBuffer creates a writer sharing an enclosing operation.
func NewBudgetBuffer(budget *DecodeBudget) *BitBuffer { return &BitBuffer{budget: budget} }

// CheckOutput enforces the independent complete-value output ceiling.
func (bb *BitBuffer) CheckOutput(count uint64) error {
	if bb.decodeBudget().err != nil {
		return bb.decodeBudget().err
	}
	if !bb.decodeBudget().outputLimited {
		return nil
	}
	limit := bb.decodeBudget().operational.MaxOutputBytes
	if limit != 0 && count > limit {
		return bb.resourceError("output bytes exceeded")
	}
	return nil
}

// ChargeLocatedReport checks all location-size products and sums before the
// report allocation. Locations themselves refer only to the original input.
func (bb *BitBuffer) ChargeLocatedReport(location Location, base uint64) error {
	spans := uint64(len(location.Spans))
	path := uint64(len(location.Path))
	if spans > math.MaxUint64/16 {
		return bb.resourceError("report location product overflows")
	}
	bytes := spans * 16
	if bytes > math.MaxUint64-base {
		return bb.resourceError("report size overflows")
	}
	bytes += base
	if path > math.MaxUint64-bytes {
		return bb.resourceError("report path size overflows")
	}
	bytes += path
	return bb.ChargeReport(location, bytes)
}

// ChargeOpenTypeFraming reserves the determinants inside a replayed field.
// X.691 (02/2021) §11.9.3.8.1 requires every nonfinal fragment except the
// last fragmented part to use 64K octets. A 16K..48K tail adds one fragmented
// part, and every value has a final short/two-octet (possibly zero) determinant.
// This charges replay without inspecting or copying its received contents.
func (bb *BitBuffer) ChargeOpenTypeFraming(octets uint64) error {
	if octets > bb.openTypeMaximum() {
		return bb.resourceError("open type bytes exceeded")
	}
	fragments := octets/65536 + 1
	if octets%65536 >= 16384 {
		fragments++
	}
	for range fragments {
		if err := bb.ChargeFragment(); err != nil {
			return err
		}
	}
	return nil
}

// CopyReplay checks one received result's output, work and storage before copying.
func CopyReplay(wire WireSpan, budget *DecodeBudget) ([]byte, error) {
	bb := NewBudgetBuffer(budget)
	if err := bb.CheckOutput(uint64(wire.Len())); err != nil {
		return nil, err
	}
	if err := bb.ChargeAllocation(uint64(wire.Len()), 1); err != nil {
		return nil, err
	}
	return wire.bytes()
}

// CopyOpaque preserves opaque contents under the enclosing operation's limits.
func CopyOpaque(value OpaqueOpenType, budget *DecodeBudget) ([]byte, error) {
	if value.image.Present() {
		return CopyReplay(value.image, budget)
	}
	bb := NewBudgetBuffer(budget)
	if err := bb.CheckOutput(uint64(len(value.bytes))); err != nil {
		return nil, err
	}
	if err := bb.ChargeAllocation(uint64(len(value.bytes)), 1); err != nil {
		return nil, err
	}
	return append([]byte(nil), value.bytes...), nil
}

func EncodeBudgetValue(options ...EncodeOption) (DecodeBudget, error) {
	var raw Limits
	for _, option := range options {
		if option.hasLimits {
			raw = option.limits
		}
	}
	var budget DecodeBudget
	err := initializeOperationBudget(&budget, raw)
	return budget, err
}
