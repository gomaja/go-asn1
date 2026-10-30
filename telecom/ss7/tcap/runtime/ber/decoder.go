// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/decoder.go; SHA-256 e03c3880fe726c02ad5e225d1d0bfcf43385e567c73925673c7db8db71a4d9ab.
package ber

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
	"math/big"
	"unicode/utf8"
)

type berWorkBudget struct {
	options         []DecodeOption // reused only if the root is rejected by its tag.
	stringSource    *byte
	elements, bytes int
	limits          DecodeLimits
	// form is the caller's BER form marker, recorded for every segment.
	form *berFormState
}

// newBERWorkBudget starts the shared budget of one recursive string decode.
// It keeps the caller's form marker, so each segment's BER form is recorded.
// The budget is returned by value so a caller can keep it on its stack.
func newBERWorkBudget(options []DecodeOption) (berWorkBudget, error) {
	config, err := decodeOptions(options)
	if err != nil {
		return berWorkBudget{}, err
	}
	return berWorkBudget{limits: config.limits, form: config.form, options: options}, nil
}

func (budget *berWorkBudget) charge(size int) error {
	if size < 0 || budget.elements < 0 || budget.elements >= budget.limits.MaxElements ||
		budget.bytes < 0 || budget.bytes > budget.limits.MaxWork {
		return fmt.Errorf("%w: BER element or total-work limit exceeded", ErrResourceLimit)
	}
	if size > budget.limits.MaxWork-budget.bytes {
		return fmt.Errorf("%w: BER element or total-work limit exceeded", ErrResourceLimit)
	}
	budget.elements++
	budget.bytes += size
	return nil
}

// DecodeTag reads an ASN.1 tag from data and returns the tag plus bytes consumed.
func DecodeTag(data []byte) (tag.Tag, int, error) {
	if len(data) == 0 {
		return tag.Tag{}, 0, ErrTruncated
	}

	b := data[0]
	t := tag.Tag{
		Class:       tag.Class(b >> 6),
		Constructed: b&0x20 != 0,
	}

	tagNum := int(b & 0x1F)
	if tagNum < 31 {
		t.Number = tagNum
		return t, 1, nil
	}

	// Long form tag number.
	offset := 1
	t.Number = 0
	for {
		if offset >= len(data) {
			return tag.Tag{}, 0, ErrTruncated
		}
		b = data[offset]
		offset++
		group := int(b & 0x7F)
		// X.690 (02/2021) §8.1.2.4–8.1.2.5 and Erratum 1
		// (09/2021, Figure 4): the first group is nonzero and the
		// accumulated number must fit the tag representation.
		if offset == 2 && group == 0 || t.Number > math.MaxInt>>7 ||
			t.Number == math.MaxInt>>7 && group > math.MaxInt&0x7f {
			return tag.Tag{}, 0, fmt.Errorf("%w: non-minimal or overflowing high-tag number", ErrInvalidTag)
		}
		t.Number = (t.Number << 7) | group
		if b&0x80 == 0 {
			break
		}
	}
	if t.Number < 31 {
		return tag.Tag{}, 0, fmt.Errorf("%w: high-tag form for tag number %d", ErrInvalidTag, t.Number)
	}
	return t, offset, nil
}

// DecodeLength reads a BER length field from data and returns the length,
// whether it's indefinite, and bytes consumed.
func DecodeLength(data []byte) (length int, indefinite bool, consumed int, err error) {
	if len(data) == 0 {
		return 0, false, 0, ErrTruncated
	}

	b := data[0]
	if b < 128 {
		return int(b), false, 1, nil
	}
	if b == 0x80 {
		return 0, true, 1, nil
	}

	numBytes := int(b & 0x7F)
	// X.690 (02/2021) §8.1.3.5 permits up to 126 subsequent octets;
	// 0xff is reserved. Leading zero length octets are valid in BER.
	if numBytes == 0 || numBytes == 127 {
		return 0, false, 0, fmt.Errorf("%w: reserved length-of-length (%d bytes)", ErrInvalidLength, numBytes)
	}
	if 1+numBytes > len(data) {
		return 0, false, 0, ErrTruncated
	}

	// X.690 (02/2021) §8.1.3: keep the definite length unsigned until it
	// has been checked against the host's slice-index range.
	var decoded uint64
	for _, octet := range data[1 : 1+numBytes] {
		if decoded > math.MaxUint64>>8 {
			return 0, false, 0, fmt.Errorf("%w: length overflows uint64", ErrInvalidLength)
		}
		decoded = decoded<<8 | uint64(octet)
	}
	if decoded > uint64(math.MaxInt) {
		return 0, false, 0, fmt.Errorf("%w: length %d exceeds host int", ErrInvalidLength, decoded)
	}
	return int(decoded), false, 1 + numBytes, nil
}

// DecodeTLV reads one complete TLV element from data.
// Returns the tag, bytes consumed, and the value bytes.
//
// With TrackBERForm in options, it records a length or universal-type form
// that DER would change, so every typed decoder built on it reports the same
// forms as ValidateBERElement.
// Delimiting checks framing and traversal budgets for either length form.
// Nested universal/schema validation belongs to ValidateBERElement and typed
// codecs. X.690 (02/2021) §§8.1.3,8.1.5; NULL semantics are in §8.8.1.
func DecodeTLV(data []byte, options ...DecodeOption) (tag.Tag, int, []byte, error) {
	config, configErr := decodeOptions(options)
	if configErr != nil {
		return tag.Tag{}, 0, nil, configErr
	}
	if len(options) != 0 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			if decodedTag, total, value, err, handled := decodeValidatedTLV(data, context, config.form); handled {
				return decodedTag, total, value, err
			}
		}
	}
	return decodeTLV(data, config.limits, config.form)
}

// decodeTLV is DecodeTLV with its options already resolved, so recursive
// decoders read each segment without building an option list.
func decodeTLV(data []byte, limits DecodeLimits, form *berFormState) (tag.Tag, int, []byte, error) {
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}

	// X.690 (02/2021) §8.1.5: EOC terminates indefinite contents;
	// it is never a value returned by this prefix decoder.
	if t.Class == tag.ClassUniversal && t.Number == 0 {
		return tag.Tag{}, 0, nil, fmt.Errorf("%w: standalone BER end-of-contents", ErrInvalidTag)
	}

	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}

	if tagLen < 0 || tagLen > len(data) {
		return tag.Tag{}, 0, nil, ErrTruncated
	}
	if lenLen < 0 || lenLen > len(data)-tagLen {
		return tag.Tag{}, 0, nil, ErrTruncated
	}
	headerLen := tagLen + lenLen

	if indefinite {
		if !t.Constructed {
			return tag.Tag{}, 0, nil, fmt.Errorf("%w: indefinite length used with primitive tag %s", ErrInvalidLength, t)
		}
		// Scan for end-of-contents octets (0x00, 0x00).
		pos := headerLen
		depth := 0
		elements := 0
		for {
			if pos < headerLen || pos > len(data) {
				return tag.Tag{}, 0, nil, ErrInvalidLength
			}
			if pos-headerLen > limits.MaxWork || elements > limits.MaxElements {
				return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER scan work limit exceeded", ErrResourceLimit)
			}
			if len(data)-pos < 2 {
				return tag.Tag{}, 0, nil, ErrTruncated
			}
			if data[pos] == 0x00 && data[pos+1] == 0x00 {
				if depth == 0 {
					value := data[headerLen:pos]
					markBERForm(form, t, data[tagLen:headerLen], true, nil)
					return t, pos + 2, value, nil
				}
				depth--
				pos += 2
				continue
			}
			// Skip nested TLVs.
			if elements >= limits.MaxElements {
				return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER scan element limit exceeded", ErrResourceLimit)
			}
			elements++
			innerTag, innerTagLen, err := DecodeTag(data[pos:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			if innerTag.Class == tag.ClassUniversal && innerTag.Number == 0 {
				return tag.Tag{}, 0, nil, fmt.Errorf("%w: malformed BER end-of-contents", ErrInvalidTag)
			}
			if innerTagLen < 0 || innerTagLen > len(data)-pos {
				return tag.Tag{}, 0, nil, ErrTruncated
			}
			innerLen, innerIndef, innerLenLen, err := DecodeLength(data[pos+innerTagLen:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			if innerLenLen < 0 || innerLenLen > len(data)-pos-innerTagLen {
				return tag.Tag{}, 0, nil, ErrTruncated
			}
			start := pos + innerTagLen + innerLenLen
			if innerIndef {
				if !innerTag.Constructed {
					return tag.Tag{}, 0, nil, fmt.Errorf("%w: indefinite length used with primitive tag %s", ErrInvalidLength, innerTag)
				}
				if depth >= limits.MaxDepth {
					return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)
				}
				depth++
				pos = start
			} else {
				if start > len(data) {
					return tag.Tag{}, 0, nil, ErrTruncated
				}
				if innerLen > len(data)-start {
					return tag.Tag{}, 0, nil, ErrTruncated
				}
				pos = start + innerLen
			}
		}
	}

	if headerLen > len(data) {
		return tag.Tag{}, 0, nil, ErrTruncated
	}
	if length > len(data)-headerLen {
		return tag.Tag{}, 0, nil, ErrTruncated
	}
	end := headerLen + length
	if end > limits.MaxWork {
		return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
	}
	markBERForm(form, t, data[tagLen:headerLen], false, data[headerLen:end])
	return t, end, data[headerLen:end], nil
}

// ValidateDERElement verifies that data contains exactly one DER TLV.
// Without a schema, a universal SET is accepted if either SET or SET OF order
// holds. IMPLICIT application, context-specific and private SETs cannot be
// recognized here; their ordering remains the schema-aware caller's responsibility.
// Reported byte offsets are relative to data.
func ValidateDERElement(data []byte) error {
	n, err := ValidateDERTLV(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ErrExtraData
	}
	return nil
}

// ValidateDERTLV verifies one definite-length DER TLV and returns its size.
// It rejects universal SETs that satisfy neither SET nor SET OF order
// (X.690 (02/2021) §§10.3, 11.6). Byte offsets are relative to data.
func ValidateDERTLV(data []byte) (int, error) {
	return validateDERTLV(data, 0, DefaultDecodeLimits().MaxDepth, 0)
}

// ValidateDEREncodedElement validates a caller-supplied encoding without
// imposing the depth budget used when examining untrusted DER input.
// It rejects universal SETs that satisfy neither SET nor SET OF order
// (X.690 (02/2021) §§10.3, 11.6). Byte offsets are relative to data.
func ValidateDEREncodedElement(data []byte) error {
	n, err := validateDERTLV(data, 0, len(data), 0)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ErrExtraData
	}
	return nil
}

func validateDERTLV(data []byte, depth, maxDepth, baseOffset int) (int, error) {
	if depth > maxDepth {
		return 0, fmt.Errorf("%w: DER nesting depth exceeded", ErrResourceLimit)
	}
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return 0, err
	}
	if tagLen < 0 || tagLen > len(data) {
		return 0, ErrTruncated
	}
	// X.690 (02/2021) 8.1.2.2 and 8.1.2.4 require the shortest
	// identifier representation for the decoded tag number.
	if canonical := t.Encode(); !bytes.Equal(data[:tagLen], canonical) {
		return 0, fmt.Errorf("%w: identifier is not encoded in its shortest form", ErrInvalidTag)
	}
	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return 0, err
	}
	if lenLen < 0 || lenLen > len(data)-tagLen {
		return 0, ErrTruncated
	}
	if indefinite {
		return 0, ErrIndefiniteLength
	}
	// X.690 (02/2021) 10.1 requires DER lengths to use the minimum
	// number of octets.
	if canonical := EncodeLength(length); !bytes.Equal(data[tagLen:tagLen+lenLen], canonical) {
		return 0, fmt.Errorf("%w: DER length is not encoded in its shortest form", ErrInvalidLength)
	}

	headerLen := tagLen + lenLen
	if length > len(data)-headerLen {
		return 0, ErrTruncated
	}
	end := headerLen + length
	value := data[headerLen:end]
	if t.Class == tag.ClassUniversal {
		if err := validateDERUniversalValue(t, value); err != nil {
			return 0, err
		}
	}
	if t.Class == tag.ClassUniversal && t.Number == tag.TagReal {
		if t.Constructed {
			return 0, fmt.Errorf("%w: DER REAL must be primitive", ErrInvalidTag)
		}
		value := data[headerLen:end]
		if len(value) != 0 && value[0]&0xc0 == 0 {
			// X.690 (02/2021) §8.5.8 reserves every decimal form except
			// NR1 to NR3 in BER too, before §11.3.2 normalization.
			if value[0] < 1 || value[0] > 3 {
				_, err := decodeRealContents(value)
				return 0, err
			}
			// X.690 (02/2021) §11.3.2 and ISO 6093 NR3 determine
			// canonical decimal REALs by spelling; no numeric conversion.
			if !canonicalDecimalRealContents(value) {
				return 0, fmt.Errorf("%w: REAL is not in distinguished encoding", ErrInvalidValue)
			}
		} else {
			decoded, err := decodeRealContents(value)
			if err != nil {
				return 0, err
			}
			canonical, err := EncodeRealValue(decoded)
			if err != nil {
				return 0, err
			}
			if !bytes.Equal(value, canonical) {
				return 0, fmt.Errorf("%w: REAL is not in distinguished encoding", ErrInvalidValue)
			}
		}
	}
	if t.Constructed {
		// X.690 (02/2021) §10.3 orders SET components by class and tag
		// number (X.680 (02/2021) §8.6), with distinct tags (§27.3).
		// X.690 §11.6 orders SET OF by zero-padded complete encodings.
		// UNIVERSAL 17 does not distinguish them: retain both possibilities
		// across the entire container, and reject only if neither survives.
		isSet := t.Class == tag.ClassUniversal && t.Number == tag.TagSet
		setOrder, setOfOrder := true, true
		var previous []byte
		var previousTag tag.Tag
		offset := headerLen
		for offset < end {
			if depth >= maxDepth {
				return 0, fmt.Errorf("%w: DER nesting depth exceeded", ErrResourceLimit)
			}
			n, err := validateDERTLV(data[offset:end], depth+1, maxDepth, baseOffset+offset)
			if err != nil {
				return 0, err
			}
			if n <= 0 || n > end-offset {
				return 0, ErrInvalidLength
			}
			if isSet {
				child := data[offset : offset+n]
				childTag, _, err := DecodeTag(child)
				if err != nil {
					return 0, err
				}
				if previous != nil {
					// The primitive/constructed bit is not part of tag identity.
					setOrder = setOrder && (previousTag.Class < childTag.Class ||
						previousTag.Class == childTag.Class && previousTag.Number < childTag.Number)
					setOfOrder = setOfOrder && compareDEROctetStrings(previous, child) <= 0
				}
				previous, previousTag = child, childTag
			}
			offset += n
		}
		if isSet && !setOrder && !setOfOrder {
			return 0, fmt.Errorf("%w: DER universal SET at byte %d follows neither SET nor SET OF order", ErrInvalidValue, baseOffset)
		}
	}
	return end, nil
}

// validateDERUniversalValue applies rules that do not require a schema.
// X.690 (02/2021) §§8.1.5, 8.2–8.4, 8.6, 8.8–8.12, 8.17.1, 8.18.1,
// 8.21.1–8.22.1, 8.24.1, 8.26, 10.2, 11.1–11.2 and 11.7–11.8, including
// §8.19–8.20 subidentifier forms;
// Erratum 1 (09/2021) changes only Figure 4.
func validateDERUniversalValue(t tag.Tag, value []byte) error {
	invalid := func(reason string) error {
		return fmt.Errorf("%w: DER universal tag %d: %s", ErrInvalidValue, t.Number, reason)
	}
	if t.Number == 0 {
		return invalid("end-of-contents is not a DER value")
	}
	primitive := false
	switch t.Number {
	case tag.TagBoolean, tag.TagInteger, tag.TagEnumerated, tag.TagNull, tag.TagObjectID,
		tag.TagRelativeOID, tag.TagReal, tag.TagUTCTime, tag.TagGeneralizedTime,
		tag.TagOIDIRI, tag.TagRelativeOIDIRI, tag.TagTime, tag.TagDate,
		tag.TagTimeOfDay, tag.TagDateTime, tag.TagDuration:
		primitive = true
	case tag.TagBitString, tag.TagOctetString, tag.TagObjectDesc, tag.TagUTF8String,
		tag.TagNumericString, tag.TagPrintableString, tag.TagT61String, tag.TagVideotexString,
		tag.TagIA5String, tag.TagGraphicString, tag.TagVisibleString, tag.TagGeneralString,
		tag.TagUniversalString, tag.TagBMPString:
		primitive = true
	case tag.TagSequence, tag.TagSet, tag.TagExternal, tag.TagEmbeddedPDV, tag.TagCharacterString:
		if !t.Constructed {
			return invalid("constructed form required")
		}
	}
	if primitive && t.Constructed {
		return invalid("primitive form required")
	}
	switch t.Number {
	case tag.TagBoolean:
		if len(value) != 1 || value[0] != 0 && value[0] != 0xff {
			return invalid("BOOLEAN must be 00 or ff")
		}
	case tag.TagInteger, tag.TagEnumerated:
		if len(value) == 0 {
			return invalid("INTEGER requires contents")
		}
		if len(value) > 1 && (value[0] == 0 && value[1]&0x80 == 0 || value[0] == 0xff && value[1]&0x80 != 0) {
			return invalid("nonminimal two's-complement INTEGER")
		}
	case tag.TagBitString:
		{
			if len(value) == 0 || value[0] > 7 {
				return invalid("invalid BIT STRING unused-bit count")
			}
			if len(value) == 1 {
				if value[0] != 0 {
					return invalid("empty BIT STRING has unused bits")
				}
			} else if value[len(value)-1]&byte((1<<value[0])-1) != 0 {
				return invalid("nonzero unused BIT STRING bits")
			}
		}
	case tag.TagNull:
		if len(value) != 0 {
			return invalid("NULL has contents")
		}
	case tag.TagObjectID:
		if err := validateBase128Subidentifiers(value); err != nil {
			return invalid("invalid OBJECT IDENTIFIER")
		}
	case tag.TagRelativeOID:
		if err := validateBase128Subidentifiers(value); err != nil {
			return invalid("invalid RELATIVE-OID")
		}
	case tag.TagExternal:
		if err := validateDERExternal(value); err != nil {
			return invalid(err.Error())
		}
	case tag.TagUTF8String:
		if !utf8.Valid(value) {
			return invalid("UTF8String is not shortest-form UTF-8 scalar text")
		}
	case tag.TagEmbeddedPDV:
		if err := validateDEREmbeddedPDV(value); err != nil {
			return invalid(err.Error())
		}
	case tag.TagUTCTime:
		// X.690 (02/2021) §11.8: YYMMDDhhmmssZ.
		parsed, err := runtime.ParseUTCTime(string(value))
		if err != nil {
			return invalid(err.Error())
		}
		if !parsed.IsCanonical() {
			return invalid("UTCTime requires YYMMDDhhmmssZ")
		}
	case tag.TagGeneralizedTime:
		// X.690 (02/2021) §11.7: YYYYMMDDhhmmss[.f]Z without trailing zeros.
		parsed, err := runtime.ParseGeneralizedTime(string(value))
		if err != nil {
			return invalid(err.Error())
		}
		if !parsed.IsCanonical() {
			return invalid("GeneralizedTime requires YYYYMMDDhhmmss[.f]Z without trailing fraction zeros")
		}
	}
	return nil
}

// X.690 (02/2021) §8.17.1 encodes the associated type in X.680
// (02/2021) §36.5. Automatic tags give identification [0] EXPLICIT,
// its alternatives [0]–[5], and data-value [2] IMPLICIT OCTET STRING.
// The associated type forbids data-value-descriptor.
func validateDEREmbeddedPDV(value []byte) error {
	ident, n, choice, err := DecodeTLV(value, encodingStructureOption(value))
	if err != nil {
		return err
	}
	if ident.Class != tag.ClassContextSpecific || ident.Number != 0 || !ident.Constructed {
		return fmt.Errorf("EMBEDDED PDV identification must be [0] EXPLICIT")
	}
	alt, altLen, altValue, err := DecodeTLV(choice, encodingStructureOption(choice))
	if err != nil {
		return err
	}
	if altLen != len(choice) || alt.Class != tag.ClassContextSpecific {
		return fmt.Errorf("EMBEDDED PDV identification must contain one alternative")
	}
	checkImplicit := func(number int, constructed bool, contents []byte) error {
		return validateDERUniversalValue(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: constructed}, contents)
	}
	checkPair := func(contents []byte, first, second int) error {
		left, used, leftValue, err := DecodeTLV(contents, encodingStructureOption(contents))
		if err != nil {
			return err
		}
		if used < 0 || used > len(contents) {
			return fmt.Errorf("EMBEDDED PDV identification pair exceeds contents")
		}
		right, rightLen, rightValue, err := DecodeTLV(contents[used:], encodingStructureOption(contents[used:]))
		if err != nil {
			return err
		}
		if rightLen < 0 || rightLen > len(contents)-used {
			return fmt.Errorf("EMBEDDED PDV identification pair exceeds contents")
		}
		if used+rightLen != len(contents) || left.Class != tag.ClassContextSpecific || left.Number != 0 || left.Constructed || right.Class != tag.ClassContextSpecific || right.Number != 1 || right.Constructed {
			return fmt.Errorf("EMBEDDED PDV identification pair has invalid components")
		}
		if err := checkImplicit(first, false, leftValue); err != nil {
			return err
		}
		return checkImplicit(second, false, rightValue)
	}
	switch alt.Number {
	case 0: // syntaxes: SEQUENCE { abstract OID, transfer OID }
		if !alt.Constructed {
			return fmt.Errorf("EMBEDDED PDV syntaxes must be constructed")
		}
		err = checkPair(altValue, tag.TagObjectID, tag.TagObjectID)
	case 1, 4: // syntax or transfer-syntax: OID
		if alt.Constructed {
			return fmt.Errorf("EMBEDDED PDV OID identification must be primitive")
		}
		err = checkImplicit(tag.TagObjectID, false, altValue)
	case 2: // presentation-context-id: INTEGER
		if alt.Constructed {
			return fmt.Errorf("EMBEDDED PDV context id must be primitive")
		}
		err = checkImplicit(tag.TagInteger, false, altValue)
	case 3: // context-negotiation: SEQUENCE { context id, transfer OID }
		if !alt.Constructed {
			return fmt.Errorf("EMBEDDED PDV context negotiation must be constructed")
		}
		err = checkPair(altValue, tag.TagInteger, tag.TagObjectID)
	case 5: // fixed: NULL
		if alt.Constructed {
			return fmt.Errorf("EMBEDDED PDV fixed must be primitive")
		}
		err = checkImplicit(tag.TagNull, false, altValue)
	default:
		return fmt.Errorf("EMBEDDED PDV identification alternative %d", alt.Number)
	}
	if err != nil {
		return err
	}
	if n < 0 || n > len(value) {
		return fmt.Errorf("EMBEDDED PDV data-value exceeds contents")
	}
	dataTag, dataLen, _, err := DecodeTLV(value[n:], encodingStructureOption(value[n:]))
	if err != nil {
		return err
	}
	if dataLen < 0 || dataLen > len(value)-n {
		return fmt.Errorf("EMBEDDED PDV data-value exceeds contents")
	}
	if n+dataLen != len(value) || dataTag.Class != tag.ClassContextSpecific || dataTag.Number != 2 || dataTag.Constructed {
		return fmt.Errorf("EMBEDDED PDV requires one primitive [2] data-value")
	}
	return nil
}

// validateBase128Subidentifiers checks only X.690 (02/2021) §§8.19–8.20
// syntax. Neither DER validation nor typed OID decoding limits arc width.
func validateBase128Subidentifiers(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("empty subidentifier list")
	}
	for offset := 0; offset < len(value); {
		first := true
		for {
			if offset >= len(value) {
				return fmt.Errorf("unterminated subidentifier")
			}
			b := value[offset]
			offset++
			if first && b == 0x80 {
				return fmt.Errorf("nonminimal subidentifier")
			}
			first = false
			if b&0x80 == 0 {
				break
			}
		}
	}
	return nil
}

func validateDERExternal(value []byte) error {
	// X.690 (02/2021) §8.18.1 and §§11.2–11.3: the encoding CHOICE
	// is the final component; DER uses primitive octet-aligned/arbitrary.
	decoded, err := DecodeExternalValue(value, encodingStructureOption(value))
	if err != nil {
		return err
	}
	children, err := DecodeSequenceChildren(value, encodingStructureOption(value))
	if err != nil {
		return err
	}
	choice, _, choiceContents, err := DecodeTLV(children[len(children)-1], encodingStructureOption(children[len(children)-1]))
	if err != nil {
		return err
	}
	if choice.Constructed && choice.Number != 0 {
		return fmt.Errorf("EXTERNAL DER encoding choice must be primitive")
	}
	if decoded.Encoding == runtime.ExternalArbitrary {
		// Inspect the received implicit contents before normalization; a typed
		// value no longer carries nonzero unused wire bits (X.690 §11.2.1).
		if err := validateDERUniversalValue(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagBitString}, choiceContents); err != nil {
			return err
		}
		bits := decoded.Arbitrary
		if bits.BitLength < 0 {
			return fmt.Errorf("%w: invalid EXTERNAL arbitrary bit length", ErrInvalidValue)
		}
		unused := (8 - bits.BitLength%8) % 8
		if unused < 0 || unused > 7 || unused > 0 && len(bits.Bytes) == 0 {
			return fmt.Errorf("%w: invalid EXTERNAL arbitrary unused-bit count", ErrInvalidValue)
		}
		length, err := externalBitLength(len(bits.Bytes), unused)
		if err != nil || length != bits.BitLength {
			return fmt.Errorf("%w: invalid EXTERNAL arbitrary bit length", ErrInvalidValue)
		}
		if unused > 0 && bits.Bytes[len(bits.Bytes)-1]&byte((1<<unused)-1) != 0 {
			return fmt.Errorf("EXTERNAL DER arbitrary has nonzero unused bits")
		}
	}
	return nil
}

// compareDEROctetStrings applies X.690 (02/2021) §11.6, padding the shorter
// encoding with trailing zero octets for comparison only.
func compareDEROctetStrings(left, right []byte) int {
	length := max(len(left), len(right))
	for index := 0; index < length; {
		var leftOctet, rightOctet byte
		if index < len(left) {
			leftOctet = left[index]
		}
		if index < len(right) {
			rightOctet = right[index]
		}
		if leftOctet < rightOctet {
			return -1
		}
		if leftOctet > rightOctet {
			return 1
		}
		index++
	}
	return 0
}

// DecodeSequenceChildren splits the value bytes of a constructed TLV into child TLVs.
// Returns a slice of raw child TLV byte slices.
func DecodeSequenceChildren(data []byte, options ...DecodeOption) ([][]byte, error) {
	limits, err := decodeLimits(options)
	if err != nil {
		return nil, err
	}
	if len(data) > limits.MaxWork {
		return nil, fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
	}
	var children [][]byte
	offset := 0
	for offset < len(data) {
		if len(children) >= limits.MaxElements {
			return nil, fmt.Errorf("%w: BER element limit exceeded", ErrResourceLimit)
		}
		t, total, value, err := DecodeTLV(data[offset:], options...)
		if err != nil {
			return nil, fmt.Errorf("at offset %d: %w", offset, err)
		}
		if total <= 0 || total > len(data)-offset {
			return nil, ErrInvalidLength
		}
		_ = t
		_ = value
		children = append(children, data[offset:offset+total])
		offset += total
	}
	return children, nil
}

// DecodeInteger decodes an integer from raw TLV bytes.
func DecodeInteger(data []byte, options ...DecodeOption) (int64, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagInteger {
		return 0, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", unexpectedElementError(data[:total], options), t)
	}
	if t.Constructed {
		return 0, 0, fmt.Errorf("%w: INTEGER must be primitive, got constructed", ErrInvalidTag)
	}
	if len(value) == 0 {
		return 0, 0, fmt.Errorf("%w: INTEGER value must have at least 1 byte", ErrInvalidValue)
	}
	v, err := decodeIntBytes(value)
	if err != nil {
		return 0, 0, err
	}
	return v, total, nil
}

func decodeIntBytes(b []byte) (int64, error) {
	if err := validateMinimalIntegerContents(b); err != nil {
		return 0, err
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("%w: integer too large for int64 (%d bytes)", ErrInvalidValue, len(b))
	}

	var v int64
	// Sign-extend the first byte.
	if b[0]&0x80 != 0 {
		v = -1 // All 1s.
	}
	for _, c := range b {
		if v < math.MinInt64>>8 || v > math.MaxInt64>>8 {
			return 0, fmt.Errorf("%w: integer overflows int64", ErrInvalidValue)
		}
		v = (v << 8) | int64(c)
	}
	return v, nil
}

// DecodeBigInt decodes an integer from raw TLV bytes into a *big.Int.
func DecodeBigInt(data []byte, options ...DecodeOption) (*big.Int, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagInteger {
		return nil, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", unexpectedElementError(data[:total], options), t)
	}
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: INTEGER must be primitive, got constructed", ErrInvalidTag)
	}
	v, err := DecodeBigIntValue(value)
	if err != nil {
		return nil, 0, err
	}
	return v, total, nil
}

// decodeStringSegments reads each header and primitive segment once, writing
// every leaf directly into one destination. X.690 (02/2021) §§8.6.4.1,
// 8.7.3.2, 8.23.3: only the last BIT STRING segment may have unused bits;
// restricted character string fragments retain universal OCTET STRING tags.
func decodeStringSegments(data []byte, expectedTag, depth int, budget *berWorkBudget, result *[]byte) (total int, unusedBits int, returnErr error) {
	defer func() {
		if returnErr != nil {
			var located *ElementError
			if !errors.As(returnErr, &located) {
				returnErr = &ElementError{cause: returnErr}
			}
		}
	}()
	if depth > budget.limits.MaxDepth {
		return 0, 0, fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)
	}
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != expectedTag {
		// X.690 (02/2021) §§8.6.4, 8.7.3 require every constructed
		// string segment to carry the same universal tag. A wrong root tag
		// instead selects an element outside the caller's abstract syntax.
		var cause error
		if depth != 0 {
			cause = ErrInvalidTag
		} else {
			// X.690 (02/2021) §§8.1.2, 8.1.3, 8.1.5: only a
			// complete root element can be rejected by its tag. Keep
			// malformed framing, including a missing EOC, as a BER error.
			// Reuse the resolved limits without tracking a rejected value.
			_, total, _, err := decodeTLV(data, budget.limits, nil)
			if err != nil {
				return 0, 0, err
			}
			// The root has not charged any string work. Apply the caller's
			// resolved options to the same recursive rejection check.
			cause = unexpectedElementError(data[:total], budget.options)
		}
		return 0, 0, fmt.Errorf("%w: expected universal string tag %d, got %s", cause, expectedTag, t)
	}
	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return 0, 0, err
	}
	if lenLen > len(data)-tagLen {
		return 0, 0, ErrTruncated
	}
	header := tagLen + lenLen
	if depth == 0 && header < len(data) {
		budget.stringSource = &data[header]
	}
	if indefinite && !t.Constructed {
		return 0, 0, fmt.Errorf("%w: indefinite length used with primitive tag %s", ErrInvalidLength, t)
	}
	end := len(data)
	if !indefinite {
		if length > len(data)-header {
			return 0, 0, ErrTruncated
		}
		end = header + length
	}
	if err := budget.charge(header); err != nil {
		return 0, 0, err
	}
	var contents []byte
	if !indefinite {
		contents = data[header:end]
	}
	markBERForm(budget.form, t, data[tagLen:header], indefinite, contents)
	unused := 0
	if t.Constructed {
		if *result == nil {
			*result = []byte{} // present empty, X.690 §§8.6.3, 8.7.3
		}
		pos, childIndex := header, 0
		childTag := tag.TagOctetString
		if expectedTag == tag.TagBitString {
			childTag = tag.TagBitString
		}
		for {
			if indefinite && end-pos >= 2 && data[pos] == 0 && data[pos+1] == 0 {
				if 2 > budget.limits.MaxWork-budget.bytes {
					return 0, 0, fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
				}
				budget.bytes += 2
				pos += 2
				break
			}
			if pos == end {
				if indefinite {
					return 0, 0, ErrTruncated
				}
				break
			}
			if unused != 0 {
				return 0, 0, fmt.Errorf("%w: non-final BIT STRING segment has unused bits", ErrInvalidValue)
			}
			if depth >= budget.limits.MaxDepth {
				return 0, 0, &ElementError{offset: pos, childIndexes: []int{childIndex}, cause: fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)}
			}
			n, childUnused, err := decodeStringSegments(data[pos:end], childTag, depth+1, budget, result)
			if err != nil {
				var located *ElementError
				if errors.As(err, &located) {
					return 0, 0, &ElementError{offset: pos + located.offset, childIndexes: append([]int{childIndex}, located.childIndexes...), cause: located.cause}
				}
				return 0, 0, err
			}
			childIndex++
			if n <= 0 || n > end-pos {
				return 0, 0, ErrInvalidLength
			}
			pos += n
			unused = childUnused
		}
		end = pos
	} else {
		work := end - header
		if work > budget.limits.MaxWork-budget.bytes {
			return 0, 0, fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
		}
		budget.bytes += work
		if expectedTag == tag.TagBitString {
			if err := validatePrimitiveBitStringContents(contents); err != nil {
				return 0, 0, err
			}
			unused = int(contents[0])
			contents = contents[1:]
		}
		// Bound the destination before append, even for an indefinite parent.
		if len(contents) > budget.limits.MaxWork-len(*result) {
			return 0, 0, fmt.Errorf("%w: BER string destination limit exceeded", ErrResourceLimit)
		}
		if depth == 0 {
			*result = contents // clean primitive values retain the borrowed fast path
			if unused != 0 && len(contents) != 0 && contents[len(contents)-1]&byte((1<<unused)-1) != 0 {
				*result = bytes.Clone(contents)
			}
		} else {
			*result = append(*result, contents...)
		}
		if unused != 0 && len(contents) != 0 && contents[len(contents)-1]&byte((1<<unused)-1) != 0 {
			(*result)[len(*result)-1] &= byte(0xff << unused)
		}
	}
	return end, unused, nil
}

// DecodeNull decodes a NULL from raw TLV bytes.
func DecodeNull(data []byte, options ...DecodeOption) (int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagNull {
		return 0, fmt.Errorf("%w: expected NULL tag, got %s", unexpectedElementError(data[:total], options), t)
	}
	if t.Constructed {
		return 0, fmt.Errorf("%w: X.690 (02/2021) §8.8.1 requires primitive NULL", ErrInvalidTag)
	}
	if len(value) != 0 {
		return 0, fmt.Errorf("%w: NULL value must be empty, got %d bytes", ErrInvalidValue, len(value))
	}
	return total, nil
}

// DecodeObjectIdentifier decodes an OID from raw TLV bytes.
func DecodeObjectIdentifier(data []byte, options ...DecodeOption) (runtime.ObjectIdentifier, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return runtime.ObjectIdentifier{}, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagObjectID {
		return runtime.ObjectIdentifier{}, 0, fmt.Errorf("%w: expected primitive OBJECT IDENTIFIER, got %s", unexpectedElementError(data[:total], options), t)
	}
	if t.Constructed {
		return runtime.ObjectIdentifier{}, 0, fmt.Errorf("%w: OBJECT IDENTIFIER must be primitive", ErrInvalidTag)
	}
	oid, err := DecodeOIDValue(value)
	if err != nil {
		return runtime.ObjectIdentifier{}, 0, err
	}
	return oid, total, nil
}

// DecodeString decodes a string type (UTF8, IA5, PrintableString, etc.) from raw TLV bytes.
// The caller provides the expected tag number.
func DecodeString(data []byte, expectedTag int, options ...DecodeOption) (string, int, error) {
	budget, err := newBERWorkBudget(options)
	if err != nil {
		return "", 0, err
	}
	var encoded []byte
	total, _, err := decodeStringSegments(data, expectedTag, 0, &budget, &encoded)
	if err != nil {
		return "", 0, err
	}
	decoded, err := decodeStringValueTagOptions(expectedTag, encoded, budget.stringSource, options)
	return decoded, total, err
}

// PeekTag reads the tag from data without consuming it.
func PeekTag(data []byte) (tag.Tag, error) {
	t, _, err := DecodeTag(data)
	return t, err
}

// DecodeIntegerValue decodes an integer from raw value bytes.
func DecodeIntegerValue(value []byte) (int64, error) {
	return decodeIntBytes(value)
}

// DecodeImplicitBitStringValue decodes primitive or constructed BIT STRING
// contents after an implicit tag has been consumed. X.690 (02/2021) 8.6.1
// permits both forms and 8.6.4.1 requires recursive, ordered segments.
func DecodeImplicitBitStringValue(constructed bool, value []byte, options ...DecodeOption) ([]byte, int, error) {
	if err := checkTCAPStringForm(constructed, tag.TagBitString, options); err != nil {
		return nil, 0, err
	}
	if constructed {
		MarkBERNonCanonical(options)
	}
	decoded, unused, err := decodeBitStringValue(constructed, value, options...)
	if err == nil && !constructed && len(options) != 0 && isGeneratedDecodeContext(options[0]) {
		decoded = bytes.Clone(decoded)
	}
	return decoded, unused, err
}

// DecodeImplicitOctetStringValue decodes the contents of an implicitly tagged
// OCTET STRING. Constructed segments retain their universal tag (ITU-T X.690
// (02/2021) §§8.7.3.2, 8.14.4).
func DecodeImplicitOctetStringValue(constructed bool, value []byte, options ...DecodeOption) ([]byte, error) {
	if err := checkTCAPStringForm(constructed, tag.TagOctetString, options); err != nil {
		return nil, err
	}
	if !constructed {
		if err := ValidateDecodeOptions(options...); err != nil {
			return nil, err
		}
		if len(options) != 0 && isGeneratedDecodeContext(options[0]) {
			return bytes.Clone(value), nil
		}
		return value, nil
	}
	MarkBERNonCanonical(options)
	budget, err := newBERWorkBudget(options)
	if err != nil {
		return nil, err
	}
	return decodeStringContents(value, tag.TagOctetString, &budget)
}

// decodeStringContents handles an implicit constructor without allocating
// a synthetic outer TLV. Its segments share both destination and work budget.
func decodeStringContents(value []byte, segmentTag int, budget *berWorkBudget) ([]byte, error) {
	if err := budget.charge(0); err != nil {
		return nil, err
	}
	result := []byte{}
	for offset := 0; offset < len(value); {
		n, unused, err := decodeStringSegments(value[offset:], segmentTag, 1, budget, &result)
		if err != nil {
			return nil, err
		}
		if n <= 0 || n > len(value)-offset {
			return nil, ErrInvalidLength
		}
		offset += n
		if offset < len(value) && unused != 0 {
			return nil, fmt.Errorf("%w: non-final BIT STRING segment has unused bits", ErrInvalidValue)
		}
	}
	return result, nil
}

func decodeBitStringValue(constructed bool, value []byte, options ...DecodeOption) ([]byte, int, error) {
	budget, err := newBERWorkBudget(options)
	if err != nil {
		return nil, 0, err
	}
	if !constructed {
		if err := budget.charge(len(value)); err != nil {
			return nil, 0, err
		}
		decoded, unused, err := decodePrimitiveBitStringValue(value)
		if err == nil && unused != 0 && len(value) > 1 && value[len(value)-1]&byte((1<<unused)-1) != 0 {
			MarkBERNonCanonical(options)
		}
		return decoded, unused, err
	}
	if err := budget.charge(0); err != nil {
		return nil, 0, err
	}
	return decodeBitStringValueBounded(true, value, 0, &budget)
}

func decodeBitStringValueBounded(constructed bool, value []byte, depth int, budget *berWorkBudget) ([]byte, int, error) {
	if !constructed {
		return decodePrimitiveBitStringValue(value)
	}
	result := []byte{}
	unused := 0
	for offset := 0; offset < len(value); {
		if depth >= budget.limits.MaxDepth {
			return nil, 0, fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)
		}
		n, childUnused, err := decodeStringSegments(value[offset:], tag.TagBitString, depth+1, budget, &result)
		if err != nil {
			return nil, 0, err
		}
		if n <= 0 || n > len(value)-offset {
			return nil, 0, ErrInvalidLength
		}
		offset += n
		if offset < len(value) && childUnused != 0 {
			return nil, 0, fmt.Errorf("%w: non-final BIT STRING segment has unused bits", ErrInvalidValue)
		}
		unused = childUnused
	}
	return result, unused, nil
}

func decodePrimitiveBitStringValue(value []byte) ([]byte, int, error) {
	if err := validatePrimitiveBitStringContents(value); err != nil {
		return nil, 0, err
	}
	decoded, unused := value[1:], int(value[0])
	// X.690 (02/2021) §§8.6.2.1–8.6.2.2: unused positions are
	// not part of the abstract value. BER accepts their received bits;
	// copy before clearing them so the wire bytes remain available for replay.
	if unused != 0 && len(decoded) != 0 && decoded[len(decoded)-1]&byte((1<<unused)-1) != 0 {
		decoded = bytes.Clone(decoded)
		decoded[len(decoded)-1] &= byte(0xff << unused)
	}
	return decoded, unused, nil
}

// X.690 (02/2021) §§8.6.2.2–8.6.2.3: padding is not subject to DER's
// zero-bit rule, but the count and empty-value shape are mandatory in BER.
func validatePrimitiveBitStringContents(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("%w: empty BIT STRING value", ErrInvalidValue)
	}
	unusedBits := int(value[0])
	if unusedBits > 7 {
		return fmt.Errorf("%w: BIT STRING unused bits %d out of range (0-7)", ErrInvalidValue, unusedBits)
	}
	if len(value) == 1 && unusedBits != 0 {
		return fmt.Errorf("%w: BIT STRING unused bits %d with no content bytes", ErrInvalidValue, unusedBits)
	}
	return nil
}

// DecodeStringValueTag decodes restricted-character-string contents according
// to the supplied UNIVERSAL tag number. X.690 (02/2021) sections 8.23.7 and
// 8.23.8 require four-octet UniversalString and two-octet BMPString forms.
func DecodeStringValueTag(tagNum int, value []byte) (string, error) {
	switch tagNum {
	case tag.TagUTF8String:
		if err := checkDecodedUTF8String(value, nil, nil); err != nil {
			return "", err
		}
		return string(value), nil
	case tag.TagBMPString:
		if len(value)%2 != 0 {
			return "", fmt.Errorf("%w: BMPString content length %d is not divisible by 2", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/2)
		for offset := 0; offset < len(value); {
			if len(value)-offset < 2 {
				return "", ErrTruncated
			}
			r := rune(binary.BigEndian.Uint16(value[offset : offset+2]))
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: BMPString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
			offset += 2
		}
		return string(runes), nil
	case tag.TagUniversalString:
		if len(value)%4 != 0 {
			return "", fmt.Errorf("%w: UniversalString content length %d is not divisible by 4", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/4)
		for offset := 0; offset < len(value); {
			if len(value)-offset < 4 {
				return "", ErrTruncated
			}
			codePoint := binary.BigEndian.Uint32(value[offset : offset+4])
			if codePoint > utf8.MaxRune {
				return "", fmt.Errorf("%w: UniversalString code point exceeds Unicode range", ErrInvalidValue)
			}
			r := rune(codePoint)
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: UniversalString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
			offset += 4
		}
		return string(runes), nil
	default:
		return string(value), nil
	}
}

// canonicalDecimalRealContents recognizes precisely the NR3 lexical form
// emitted by EncodeRealValue under X.690 (02/2021) §11.3.2. Callers decode
// the REAL value separately, so this only classifies the received spelling.
func canonicalDecimalRealContents(value []byte) bool {
	if len(value) < 5 || value[0] != 3 {
		return false
	}
	i := 1
	if value[i] == '-' {
		i++
	}
	if i >= len(value) || value[i] < '1' || value[i] > '9' {
		return false
	}
	lastDigit := byte(0)
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		lastDigit = value[i]
		i++
	}
	if lastDigit == '0' || len(value)-i < 3 || value[i] != '.' || value[i+1] != 'E' {
		return false
	}
	i += 2
	if value[i] == '+' {
		return len(value)-i == 2 && value[i+1] == '0'
	}
	if value[i] == '-' {
		i++
	}
	if i >= len(value) || value[i] < '1' || value[i] > '9' {
		return false
	}
	for i++; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// realExponentOctets widens the X.690 (02/2021) §8.5.7.4(d) length octet.
// Sharing the conversion keeps validation and value decoding on the same bound.
func realExponentOctets(length byte) int { return int(length) }

func decodeRealContents(value []byte) (runtime.Real, error) {
	if len(value) == 0 {
		return runtime.Real{}, nil
	}
	info := value[0]
	if info&0xc0 == 0x40 {
		if len(value) != 1 {
			return runtime.Real{}, fmt.Errorf("%w: REAL special value must contain one octet", ErrInvalidValue)
		}
		var kind runtime.RealKind
		switch info {
		case 0x40:
			kind = runtime.RealPlusInfinity
		case 0x41:
			kind = runtime.RealMinusInfinity
		case 0x42:
			kind = runtime.RealNotANumber
		case 0x43:
			kind = runtime.RealMinusZero
		default:
			return runtime.Real{}, fmt.Errorf("%w: reserved REAL special value 0x%02x", ErrInvalidValue, info)
		}
		return runtime.NewSpecialReal(kind)
	}
	if info&0x80 == 0 {
		return decodeDecimalReal(info, value[1:])
	}

	baseField := (info >> 4) & 0x03
	var baseScale int64
	switch baseField {
	case 0:
		baseScale = 1
	case 1:
		baseScale = 3
	case 2:
		baseScale = 4
	default:
		return runtime.Real{}, fmt.Errorf("%w: reserved REAL binary base", ErrInvalidValue)
	}
	scaleFactor := int64(info&0x0c) >> 2
	expLen := int(info&0x03) + 1
	offset := 1
	if info&0x03 == 3 {
		if offset >= len(value) {
			return runtime.Real{}, fmt.Errorf("%w: REAL exponent length truncated", ErrTruncated)
		}
		expLen = realExponentOctets(value[offset])
		offset++
		if expLen == 0 {
			return runtime.Real{}, fmt.Errorf("%w: REAL exponent length is zero", ErrInvalidValue)
		}
	}
	if offset > len(value) {
		return runtime.Real{}, fmt.Errorf("%w: REAL exponent offset exceeds value", ErrTruncated)
	}
	if expLen >= len(value)-offset {
		return runtime.Real{}, fmt.Errorf("%w: REAL exponent or mantissa truncated", ErrTruncated)
	}
	exponentBytes := value[offset : offset+expLen]
	if info&0x03 == 3 && len(exponentBytes) > 1 &&
		(exponentBytes[0] == 0x00 && exponentBytes[1]&0x80 == 0 || exponentBytes[0] == 0xff && exponentBytes[1]&0x80 != 0) {
		return runtime.Real{}, fmt.Errorf("%w: REAL long exponent violates the first-nine-bits rule", ErrInvalidValue)
	}
	// X.690 (02/2021) §8.5.7.4 permits nonminimal short-form REAL
	// exponents. Its first-nine-bits restriction applies to long form.
	exponent, err := decodeSignedBigIntContents(exponentBytes)
	if err != nil {
		return runtime.Real{}, fmt.Errorf("decoding REAL exponent: %w", err)
	}
	offset += expLen
	mantissa := new(big.Int).SetBytes(value[offset:])
	if mantissa.Sign() == 0 {
		return runtime.Real{}, fmt.Errorf("%w: REAL mantissa is zero", ErrInvalidValue)
	}
	if info&0x40 != 0 {
		mantissa.Neg(mantissa)
	}
	exponent.Mul(exponent, big.NewInt(baseScale))
	exponent.Add(exponent, big.NewInt(scaleFactor))
	decoded, err := runtime.NewReal(2, mantissa, exponent)
	if err != nil {
		return runtime.Real{}, fmt.Errorf("decoding REAL: %w", err)
	}
	return decoded, nil
}

func decodeDecimalReal(form byte, contents []byte) (runtime.Real, error) {
	if form != 1 && form != 2 && form != 3 {
		return runtime.Real{}, fmt.Errorf("%w: reserved REAL decimal form %d", ErrInvalidValue, form)
	}
	text := string(contents)
	for len(text) > 0 && text[0] == ' ' {
		text = text[1:]
	}
	if text == "" {
		return runtime.Real{}, fmt.Errorf("%w: empty REAL decimal form", ErrInvalidValue)
	}
	sign := 1
	if text[0] == '+' || text[0] == '-' {
		if text[0] == '-' {
			sign = -1
		}
		text = text[1:]
	}
	if text == "" {
		return runtime.Real{}, fmt.Errorf("%w: REAL decimal form has no digits", ErrInvalidValue)
	}

	integerPart := text
	fractionPart := ""
	exponent := new(big.Int)
	if form >= 2 {
		mark := -1
		for index, character := range []byte(text) {
			if character == '.' || character == ',' {
				if mark >= 0 {
					return runtime.Real{}, fmt.Errorf("%w: REAL decimal form has multiple decimal marks", ErrInvalidValue)
				}
				mark = index
			}
		}
		if mark < 0 || mark >= len(text) {
			return runtime.Real{}, fmt.Errorf("%w: REAL NR%d form has no decimal mark", ErrInvalidValue, form)
		}
		integerPart = text[:mark]
		fractionAndExponent := text[mark+1:]
		if form == 2 {
			fractionPart = fractionAndExponent
		} else {
			exponentMark := -1
			for index, character := range []byte(fractionAndExponent) {
				if character == 'E' || character == 'e' {
					if exponentMark >= 0 {
						return runtime.Real{}, fmt.Errorf("%w: REAL NR3 form has multiple exponent marks", ErrInvalidValue)
					}
					exponentMark = index
				}
			}
			if exponentMark < 0 || exponentMark >= len(fractionAndExponent) {
				return runtime.Real{}, fmt.Errorf("%w: REAL NR3 form has no exponent", ErrInvalidValue)
			}
			fractionPart = fractionAndExponent[:exponentMark]
			encodedExponent := fractionAndExponent[exponentMark+1:]
			if encodedExponent == "" {
				return runtime.Real{}, fmt.Errorf("%w: REAL NR3 exponent is empty", ErrInvalidValue)
			}
			exponentText := encodedExponent
			if exponentText[0] == '+' || exponentText[0] == '-' {
				if len(exponentText) == 1 {
					return runtime.Real{}, fmt.Errorf("%w: REAL NR3 exponent has no digits", ErrInvalidValue)
				}
				exponentText = exponentText[1:]
			}
			if !decimalDigits(exponentText) {
				return runtime.Real{}, fmt.Errorf("%w: REAL NR3 exponent contains a non-digit", ErrInvalidValue)
			}
			exponent.SetString(encodedExponent, 10)
			if exponent.Sign() == 0 && encodedExponent[0] != '+' {
				return runtime.Real{}, fmt.Errorf("%w: REAL NR3 zero exponent requires a plus sign", ErrInvalidValue)
			}
		}
	}
	if !decimalDigits(integerPart) && integerPart != "" || !decimalDigits(fractionPart) && fractionPart != "" {
		return runtime.Real{}, fmt.Errorf("%w: REAL decimal form contains a non-digit", ErrInvalidValue)
	}
	if integerPart == "" && fractionPart == "" {
		return runtime.Real{}, fmt.Errorf("%w: REAL decimal form has no digits", ErrInvalidValue)
	}
	if form == 1 && !decimalDigits(integerPart) {
		return runtime.Real{}, fmt.Errorf("%w: REAL NR1 form is not an integer", ErrInvalidValue)
	}

	digits := integerPart + fractionPart
	mantissa := new(big.Int)
	mantissa.SetString(digits, 10)
	if mantissa.Sign() == 0 {
		return runtime.Real{}, fmt.Errorf("%w: plus or minus zero requires its dedicated REAL encoding", ErrInvalidValue)
	}
	if sign < 0 {
		mantissa.Neg(mantissa)
	}
	exponent.Sub(exponent, big.NewInt(int64(len(fractionPart))))
	decoded, err := runtime.NewReal(10, mantissa, exponent)
	if err != nil {
		return runtime.Real{}, fmt.Errorf("decoding decimal REAL: %w", err)
	}
	return decoded, nil
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// DecodeOIDValue decodes an OID from raw value bytes.
func DecodeOIDValue(value []byte) (runtime.ObjectIdentifier, error) {
	oid, err := runtime.ObjectIdentifierFromEncoded(string(value))
	return oid, oidDecodeError(err)
}

func oidDecodeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, runtime.ErrTruncatedOID) {
		return fmt.Errorf("%w: %v", ErrTruncated, err)
	}
	return fmt.Errorf("%w: %v", ErrInvalidValue, err)
}

// DecodeSequenceContent decodes the outer SEQUENCE tag and returns the content bytes
// and total bytes consumed. This is used by generated UnmarshalBER methods.
func DecodeSequenceContent(data []byte, options ...DecodeOption) ([]byte, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagSequence {
		return nil, 0, fmt.Errorf("%w: expected SEQUENCE, got %s", unexpectedElementError(data[:total], options), t)
	}
	if !t.Constructed {
		return nil, 0, fmt.Errorf("%w: primitive SEQUENCE", ErrInvalidTag)
	}
	return value, total, nil
}

// DecodeConstructedContent decodes any constructed TLV and returns the content bytes,
// the tag, and total bytes consumed. Used for APPLICATION-tagged types.
func DecodeConstructedContent(data []byte, options ...DecodeOption) (tag.Tag, []byte, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return tag.Tag{}, nil, 0, err
	}
	return t, value, total, nil
}

// DecodeBigIntValue interprets contents octets as an arbitrary-width INTEGER.
//
// It is the counterpart to DecodeIntegerValue, which caps at 8 octets because
// its result is an int64. An ASN.1 INTEGER is unbounded, and unconstrained
// ones legitimately exceed 64 bits: RFC 5280 §4.1.2.2 requires certificate
// users to handle a serialNumber of up to 20 octets.
func DecodeBigIntValue(value []byte) (*big.Int, error) {
	if err := validateMinimalIntegerContents(value); err != nil {
		return nil, err
	}
	return decodeSignedBigIntContents(value)
}

// X.690 (02/2021) §8.3.2 applies to INTEGER and, by §8.4, ENUMERATED.
// Redundant sign octets are invalid BER, including under implicit tagging.
func validateMinimalIntegerContents(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("%w: X.690 (02/2021) §8.3.1 requires INTEGER contents", ErrInvalidValue)
	}
	if len(value) > 1 && (value[0] == 0 && value[1]&0x80 == 0 ||
		value[0] == 0xff && value[1]&0x80 != 0) {
		return fmt.Errorf("%w: X.690 (02/2021) §8.3.2 forbids redundant INTEGER sign octets", ErrInvalidValue)
	}
	return nil
}

// REAL exponent octets have their own BER rules in X.690 §8.5.7.4.
func decodeSignedBigIntContents(value []byte) (*big.Int, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty signed integer", ErrInvalidValue)
	}
	v := new(big.Int)
	if value[0]&0x80 != 0 {
		notBytes := make([]byte, len(value))
		for i, b := range value {
			notBytes[i] = ^b
		}
		v.SetBytes(notBytes)
		v.Add(v, big.NewInt(1))
		v.Neg(v)
		return v, nil
	}
	v.SetBytes(value)
	return v, nil
}
