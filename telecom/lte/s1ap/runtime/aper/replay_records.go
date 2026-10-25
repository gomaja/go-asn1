// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_records.go; SHA-256 678dfe13d16c97c0b8d73aceeb6f6685df6750df0200ed8a8a22b148077c00f6.
package aper

// WithRecords combines stored padding state with the truncated or recovered
// extension addition recorded in decoded. The shared padding entry is unchanged.
func (f FinalPadding) WithRecords(decoded FinalPadding) FinalPadding {
	if decoded.bits == nil || decoded.bits.truncated == nil {
		return f
	}
	if f.bits == nil {
		return decoded
	}
	merged := *f.bits
	merged.truncated = decoded.bits.truncated
	return FinalPadding{bits: &merged}
}
