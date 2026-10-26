// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/read_work.go; SHA-256 3ed816669c36604624c24af4e4c0fad0ab47c41f3db3868a7dc97369a41c3cac.
package aper

// checkReadBits checks total work before examining bits or allocating their copy.
// A limit failure is sticky, even if a caller discards its error.
func (bb *BitBuffer) checkReadBits(bits uint64) error {
	budget := bb.decodeBudget()
	if budget.err != nil {
		return budget.err
	}
	if bits > uint64(budget.limits.MaxWork)-budget.usage.Work {
		return bb.resourceError("PER total-work bit limit exceeded")
	}
	return nil
}

func (bb *BitBuffer) examineReadBits(bits uint64) error {
	if err := bb.checkReadBits(bits); err != nil {
		return err
	}
	budget := bb.decodeBudget()
	budget.usage.Work += bits
	budget.publish()
	return nil
}
