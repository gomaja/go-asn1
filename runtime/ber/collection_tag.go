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

// decodeDualTaggedChoiceContent accepts a complete tagged CHOICE TLV or its
// alternative TLV after an unwritten-mode outer tag. X.680 (02/2021) §31.2.7
// allows the replacement form; X.690 (02/2021) §8.14.3 requires a complete
// base encoding inside an EXPLICIT wrapper. GSMA SGP.22 v2.7 Table 45 NOTE 1
// and SGP.32 v1.3 Table 27 NOTE 1 require the complete response object in
// their binding.
// The referenced CHOICE decoder verifies that the inner tag is an alternative.
func decodeDualTaggedChoiceContent(content []byte, inner tag.Tag, canonicalExplicit bool, opts ...DecodeOption) ([]byte, error) {
	actual, total, _, err := DecodeTLV(content, opts...)
	if err != nil {
		return nil, err
	}
	if total != len(content) {
		return nil, fmt.Errorf("%w: tagged CHOICE content has trailing data", ErrExtraData)
	}
	if actual.Class == inner.Class && actual.Number == inner.Number {
		if !actual.Constructed {
			return nil, fmt.Errorf("%w: tagged CHOICE must be constructed", ErrInvalidTag)
		}
		if !canonicalExplicit {
			MarkBERNonCanonical(opts)
		}
		return content, nil
	}
	rebuilt, err := EncodeConstructed(inner, content)
	if err != nil {
		return nil, err
	}
	if canonicalExplicit {
		MarkBERNonCanonical(opts)
	}
	return rebuilt, nil
}

// DecodeDualTaggedChoiceElement checks the outer tag before normalizing its
// single inner value. Both BER forms must use a constructed outer identifier.
func DecodeDualTaggedChoiceElement(data []byte, outer, inner tag.Tag, canonicalExplicit bool, opts ...DecodeOption) ([]byte, error) {
	actual, total, content, err := DecodeTLV(data, opts...)
	if err != nil {
		return nil, err
	}
	if total != len(data) {
		return nil, fmt.Errorf("%w: tagged CHOICE has trailing data", ErrExtraData)
	}
	if actual.Class != outer.Class || actual.Number != outer.Number || !actual.Constructed {
		return nil, fmt.Errorf("%w: expected constructed %s %d, got %s", ErrInvalidTag, outer.Class, outer.Number, actual)
	}
	return decodeDualTaggedChoiceContent(content, inner, canonicalExplicit, opts...)
}
