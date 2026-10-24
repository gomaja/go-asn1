// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_records.go; SHA-256 4cf8cca062cbd6d22ecae94678fdee5756726baf7b38150cdb050636975018ae.
package aper

// WithRecords combines observed final padding with the truncated or recovered
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
