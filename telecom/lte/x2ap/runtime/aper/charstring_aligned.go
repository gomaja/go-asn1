// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/charstring_aligned.go; SHA-256 b026cd1dad1bc365a7e9326cf2d4269838aa0fb15a989c325ca11c36b0976541.
package aper

// EncodeKnownMultiplierStringAligned writes the ALIGNED variant: each
// character takes B2 bits, the smallest power of two
// not below alphabetBits (ITU-T X.691 (02/2021) 30.5.2), so 8 for IA5String,
// VisibleString and PrintableString.
func EncodeKnownMultiplierStringAligned(bb *BitBuffer, s string, alphabetBits int, lb, ub int64, constrained bool) error {
	return EncodeKnownMultiplierStringAlignedExt(bb, s, alphabetBits, lb, ub, constrained, false)
}

// EncodeKnownMultiplierStringAlignedExt implements the size extension bit
// required by ITU-T X.691 (02/2021) Section 30.4.
func EncodeKnownMultiplierStringAlignedExt(bb *BitBuffer, s string, alphabetBits int, lb, ub int64, constrained, extensible bool) error {
	codec, err := identityCharacterCodec(alphabetBits)
	if err != nil {
		return err
	}
	return encodeCharacterString(bb, s, codec, lb, ub, constrained, extensible)
}

// DecodeKnownMultiplierStringAligned decodes a string encoded by
// EncodeKnownMultiplierStringAligned.
func DecodeKnownMultiplierStringAligned(bb *BitBuffer, alphabetBits int, lb, ub int64, constrained bool) (string, error) {
	return DecodeKnownMultiplierStringAlignedExt(bb, alphabetBits, lb, ub, constrained, false)
}

// DecodeKnownMultiplierStringAlignedExt implements the size extension bit
// required by ITU-T X.691 (02/2021) Section 30.4.
func DecodeKnownMultiplierStringAlignedExt(bb *BitBuffer, alphabetBits int, lb, ub int64, constrained, extensible bool) (string, error) {
	codec, err := identityCharacterCodec(alphabetBits)
	if err != nil {
		return "", err
	}
	return decodeCharacterString(bb, codec, lb, ub, constrained, extensible)
}
