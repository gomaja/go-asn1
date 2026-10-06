package per

// MaxExplicitDefaults is the number of DEFAULT components of a simple type
// that one SEQUENCE or SET can record as explicitly received.
const MaxExplicitDefaults = 64

// ExplicitDefaults returns final bits recording the DEFAULT components that a
// decoded SEQUENCE or SET value carried explicitly with their default values.
// Bit i of mask stands for the type's i-th DEFAULT component of a simple type,
// in definition order. Only a mask with a bit above the eighth allocates.
//
// X.691 (02/2021) 19.5 requires a BASIC-PER encoder to omit a DEFAULT
// component of a simple type (3.7.25) that holds its default value, and a
// decoder accepts it either way. A new value is encoded that way. A decoded
// value records which components the sender included anyway, so the value
// re-encodes byte-exactly while those components still hold the default.
func ExplicitDefaults(mask uint64) FinalPadding {
	if mask == 0 {
		return FinalPadding{}
	}
	if mask < uint64(len(explicitDefaultTable)) {
		return FinalPadding{bits: &explicitDefaultTable[mask]}
	}
	return FinalPadding{bits: &finalBits{explicitDefaults: mask}}
}

// explicitDefaultTable holds the record of every mask below 256, so a value
// whose explicit defaults are among the first eight DEFAULT components of a
// simple type records them without allocating. Entries are shared and never
// modified.
var explicitDefaultTable = func() (table [256]finalBits) {
	for mask := range table {
		table[mask].explicitDefaults = uint64(mask)
	}
	return table
}()

// ExplicitDefault reports whether the decoded value carried its index-th
// DEFAULT component of a simple type explicitly with the default value.
func (f FinalPadding) ExplicitDefault(index int) bool {
	if f.bits == nil || index < 0 || index >= MaxExplicitDefaults {
		return false
	}
	return f.bits.explicitDefaults&(uint64(1)<<uint(index)) != 0
}

// FinalPaddingOf returns the final bits holding padding, without allocating.
// An APER SEQUENCE or SET whose PERPadding_ records explicit defaults keeps
// the padding captured after the value this way.
func FinalPaddingOf(padding CompletePadding) FinalPadding {
	return finalPaddingOf(padding)
}

// WithExplicitDefaults returns f together with the explicit DEFAULT
// components recorded in decoded. A top-level decode uses it to keep, next to
// the final bits it captured, what the value recorded while it was decoded.
func (f FinalPadding) WithExplicitDefaults(decoded FinalPadding) FinalPadding {
	if decoded.bits == nil || decoded.bits.explicitDefaults == 0 {
		return f
	}
	if f.bits == nil {
		return decoded
	}
	merged := *f.bits
	merged.explicitDefaults = decoded.bits.explicitDefaults
	return FinalPadding{bits: &merged}
}
