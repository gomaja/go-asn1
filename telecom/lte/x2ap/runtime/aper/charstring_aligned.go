// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/charstring_aligned.go; SHA-256 202cfcfb78e059dd183eb9515a3eefdae5c85b565c4f414d892afc81f2d51a13.
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

// EncodeVisibleStringAligned encodes the unconstrained URI-Address profile
// (TS 36.423 V19.1.0 §9.3.5). X.691 (02/2021) §§30.5.1–30.5.4 retain
// only ISO 646 character values 32 through 126, in one aligned octet.
func EncodeVisibleStringAligned(bb *BitBuffer, value string) error {
	codec, _ := identityCharacterCodec(7)
	codec.visible = true
	return encodeCharacterString(bb, value, codec, 0, 0, false, false)
}

// DecodeVisibleStringAligned enforces the same source alphabet on receipt.
func DecodeVisibleStringAligned(bb *BitBuffer) (string, error) {
	codec, _ := identityCharacterCodec(7)
	codec.visible = true
	return decodeCharacterString(bb, codec, 0, 0, false, false)
}
