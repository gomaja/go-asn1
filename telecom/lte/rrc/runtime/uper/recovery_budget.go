// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/recovery_budget.go; SHA-256 8be83bd1de3945714c2909541808dc93f55b3b31665abcbe81e99dfe190c7df4.
package uper

import "fmt"

// This operational limit applies only with ExtensionRecoveryTolerance. Four
// input lengths permit local provenance and replay scans while bounding
// repeated scans of recursively recovered values.
// It is independent of the wire rules in X.691 (02/2021) 11.2.1–11.2.2,
// 19.9. DecodeLimits.MaxWork separately counts all examined bits; both
// budgets must permit a read.
const recoveryWorkInputMultiple = 4

type recoveryWork struct {
	limit, used uint64
	active      bool
	err         error
	rolledBack  map[*byte]int // one entry per abandoned nonempty candidate
}

func (work *recoveryWork) recordRollback(data []byte, bitPos int) {
	if len(data) == 0 || bitPos <= 0 {
		return
	}
	if work.rolledBack == nil {
		work.rolledBack = make(map[*byte]int)
	}
	if bitPos > work.rolledBack[&data[0]] {
		work.rolledBack[&data[0]] = bitPos
	}
}

func (bb *BitBuffer) recoveryCharge(bits uint64) uint64 {
	if bits == 0 || bb.trace == nil || bb.trace.work == nil {
		return 0
	}
	if bb.trace.work.active {
		return bits // provenance or replay scan of already decoded bits
	}
	if bb.bitPos < 0 || len(bb.data) == 0 || len(bb.trace.work.rolledBack) == 0 {
		return 0
	}
	retryBefore := bb.trace.work.rolledBack[&bb.data[0]]
	if bb.bitPos >= retryBefore {
		return 0
	}
	return min(bits, uint64(retryBefore-bb.bitPos))
}

// checkRecoveryBits checks extra work before examining bits or allocating
// their copy. Work is shared by inherited buffers and never refunded.
// A limit failure is sticky, even if a caller discards or defers its error.
func (bb *BitBuffer) checkRecoveryBits(bits uint64) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if bits > uint64(budget.limits.MaxWork)-budget.usage.Work {
		return budget.fail("PER total-work bit limit exceeded")
	}
	trace := bb.trace
	if trace == nil || trace.work == nil {
		return nil
	}
	if trace.work.err != nil {
		return trace.work.err
	}
	charge := bb.recoveryCharge(bits)
	if charge > trace.work.limit-trace.work.used {
		trace.work.err = fmt.Errorf("%w: extension recovery examined %d extra bits; next read of %d extra bits exceeds %dx input budget (%d bits)", ErrResourceLimit, trace.work.used, charge, recoveryWorkInputMultiple, trace.work.limit)
		return trace.work.err
	}
	return nil
}

func (bb *BitBuffer) examineRecoveryBits(bits uint64) error {
	if err := bb.checkRecoveryBits(bits); err != nil {
		return err
	}
	budget := bb.decodeBudget()
	budget.usage.Work += bits
	budget.publish()
	if trace := bb.trace; trace != nil && trace.work != nil {
		// checkRecoveryBits proves charge <= limit-used before this addition.
		trace.work.used += bb.recoveryCharge(bits)
	}
	return nil
}
