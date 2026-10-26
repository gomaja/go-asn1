// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/extension_additions.go; SHA-256 3cf4de7d90b2621ec5e482dec407e4195453a867caec270f77c8ae8b2aa5ffed.
package aper

// ExtensionAdditions validates the extension bitmap of a SEQUENCE or SET.
// X.691 (02/2021) §§19.1, 19.7–19.9 require a present addition when the
// extension bit is set, without requiring a minimum bitmap width.
type ExtensionAdditions struct{}

// DecodeBitmapAligned decodes an APER extension bitmap and checks presence.
func (*ExtensionAdditions) DecodeBitmapAligned(bb *BitBuffer) (int64, []bool, error) {
	start := bb.BitPos()
	count, present, err := DecodeExtensionBitmapAligned(bb)
	if err != nil {
		return count, present, err
	}
	for _, set := range present {
		if set {
			return count, present, nil
		}
	}
	return 0, nil, bb.syntaxError(start, "§19.1", "extension bit set without any present addition", ErrInvalidValue)
}
