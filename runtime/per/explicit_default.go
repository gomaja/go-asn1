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
// An APER value whose PERPadding_ records explicit defaults or kept BIT
// STRINGs keeps the padding captured after the value this way.
func FinalPaddingOf(padding CompletePadding) FinalPadding {
	return finalPaddingOf(padding)
}

// KeptBitStrings returns final bits recording the BIT STRINGs with a
// NamedBitList that a decoded value received with a length other than the
// one X.691 (02/2021) 16.2 and 16.3 give a new value (NamedBitStringMinimal).
// kept[i] is the record of the type's i-th such component, alternative or
// list, in definition order (KeepAt); a nil slice records nothing and
// allocates nothing.
//
// A new value is encoded with the minimal length (EncodeNamedBitString). A
// decoded value records the received values, so that each one re-encodes
// with its received length while it is unchanged (KeptBits.Keeps).
func KeptBitStrings(kept []KeptBits) FinalPadding {
	if len(kept) == 0 {
		return FinalPadding{}
	}
	return FinalPadding{bits: &finalBits{kept: kept}}
}

// KeptBitString returns the record of the decoded value's index-th BIT
// STRING with a NamedBitList, or list of them; it is empty when the value
// received it with the minimal length or was not decoded.
func (f FinalPadding) KeptBitString(index int) KeptBits {
	if f.bits == nil || index < 0 || index >= len(f.bits.kept) {
		return KeptBits{}
	}
	return f.bits.kept[index]
}

// WithKeptBitStrings returns f together with the kept BIT STRINGs. A decoder
// that records both explicit defaults and kept BIT STRINGs combines them this
// way.
func (f FinalPadding) WithKeptBitStrings(kept []KeptBits) FinalPadding {
	if len(kept) == 0 {
		return f
	}
	if f.bits == nil {
		return KeptBitStrings(kept)
	}
	merged := *f.bits
	merged.kept = kept
	return FinalPadding{bits: &merged}
}

// WithRecords returns f together with the explicit DEFAULT components, the
// kept BIT STRING lengths and the truncated extension addition recorded in
// decoded. A top-level or contained decode uses it to keep, next to the final
// bits it captured, what the value recorded while it was decoded.
func (f FinalPadding) WithRecords(decoded FinalPadding) FinalPadding {
	if decoded.bits == nil || decoded.bits.explicitDefaults == 0 && len(decoded.bits.kept) == 0 && decoded.bits.truncated == nil {
		return f
	}
	if f.bits == nil {
		return decoded
	}
	merged := *f.bits
	merged.explicitDefaults = decoded.bits.explicitDefaults
	merged.kept = decoded.bits.kept
	merged.truncated = decoded.bits.truncated
	return FinalPadding{bits: &merged}
}
