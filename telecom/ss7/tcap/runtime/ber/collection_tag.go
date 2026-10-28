// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/collection_tag.go; SHA-256 dca9ef47e6a930e7a487bf4321dcd0e4c0992aaba6454e947efda47280113b45.
package ber

// X.690 (02/2021) §§8.1.2–8.1.3: parse all tail identifiers and
// lengths and recursively validate their contents before classifying complete
// extra elements as a type mismatch (X.690 (02/2021) §§8.1.4, 8.9.2).
func validateExtraElements(remaining []byte, opts []DecodeOption) error {
	if len(remaining) == 0 {
		return nil
	}
	config, err := unexpectedElementConfig(opts)
	if err != nil {
		return err
	}
	// One recursive scan shares MaxWork, MaxElements and MaxDepth across the
	// entire rejected contents, including the first element and every sibling.
	config.allowSiblingElements = true
	return validateBERElement(remaining, nil, config)
}
