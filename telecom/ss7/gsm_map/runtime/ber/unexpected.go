// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/unexpected.go; SHA-256 45d1517473550b918b0ff8ce049821220159e3eeeb7b4784a6aff4eff8dcf07c.
package ber

// unexpectedElementError classifies only a complete, well-formed encoding as
// an abstract-syntax mismatch. Reuse the public validator's recursive X.690
// (02/2021) §§8.1–8.26 checks, including universal form and contents rules.
// Call only on rejection paths; successful typed decodes keep their cost.
func unexpectedElementError(data []byte, options []DecodeOption) error {
	config, err := unexpectedElementConfig(options)
	if err != nil {
		return err
	}
	if err := validateBERElement(data, nil, config); err != nil {
		return err
	}
	return ErrUnexpectedElement
}

// A rejected element has no schema ownership or reusable generated proof.
// Keep the caller's limits, tolerance budget and diagnostic location, while
// excluding profile rules and scan shortcuts from this X.690-only check.
func unexpectedElementConfig(options []DecodeOption) (decodeConfig, error) {
	config, err := decodeOptions(options)
	if err != nil {
		return decodeConfig{}, err
	}
	config.form = nil
	config.positionSearch = nil
	config.collectPositionsOnly = false
	config.allowSiblingElements = false
	config.firstUTF8Only = false
	return config, nil
}
