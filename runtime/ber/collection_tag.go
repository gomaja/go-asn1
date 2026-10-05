package ber

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// DecodeTaggedCollectionElement checks an element's effective tag and returns
// the inner encoding expected by its base decoder. ITU-T X.690 (02/2021)
// §8.14 distinguishes the wrapper of EXPLICIT tagging from the replacement
// identifier of IMPLICIT tagging.
func DecodeTaggedCollectionElement(data []byte, outer tag.Tag, explicit bool, inner tag.Tag, opts ...DecodeOption) ([]byte, error) {
	actual, total, content, err := DecodeTLV(data, opts...)
	if err != nil {
		return nil, err
	}
	if total != len(data) {
		return nil, fmt.Errorf("%w: tagged element has trailing data", ErrExtraData)
	}
	if actual.Class != outer.Class || actual.Number != outer.Number {
		return nil, fmt.Errorf("%w: expected %s %d, got %s", ErrInvalidTag, outer.Class, outer.Number, actual)
	}
	if explicit {
		if !actual.Constructed {
			return nil, fmt.Errorf("%w: EXPLICIT element must be constructed", ErrInvalidTag)
		}
		_, consumed, _, innerErr := DecodeTLV(content, opts...)
		if innerErr != nil {
			return nil, fmt.Errorf("decoding EXPLICIT element: %w", innerErr)
		}
		if consumed != len(content) {
			return nil, fmt.Errorf("%w: EXPLICIT element must contain one value", ErrExtraData)
		}
		return content, nil
	}
	retagged, err := EncodeImplicitTagWithClass(inner.Class, inner.Number, data)
	if err != nil {
		return nil, err
	}
	// The outer structural walk sees a context tag, so it cannot classify
	// noncanonical BOOLEAN, REAL, or constructed string forms. Rewalk with
	// the effective base tag before the generated decoder normalizes them.
	// ITU-T X.690 (02/2021) §§8.2.1, 8.6.3, 8.7.3, 8.9.3, 11.1–11.3.
	if err := ValidateBERElement(retagged, opts...); err != nil {
		return nil, err
	}
	return retagged, nil
}
