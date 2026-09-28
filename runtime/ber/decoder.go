package ber

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"time"
	"unicode/utf8"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/tag"
)

type berWorkBudget struct {
	elements, bytes int
	limits          DecodeLimits
}

func (budget *berWorkBudget) charge(size int) error {
	budget.elements++
	if budget.elements > budget.limits.MaxElements || size > budget.limits.MaxWork-budget.bytes {
		return fmt.Errorf("%w: BER element or total-work limit exceeded", ErrInvalidValue)
	}
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
		if offset == 2 && group == 0 || t.Number > (math.MaxInt-group)>>7 {
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
	if numBytes > 4 || numBytes == 0 {
		return 0, false, 0, fmt.Errorf("%w: length field too large (%d bytes)", ErrInvalidLength, numBytes)
	}
	if 1+numBytes > len(data) {
		return 0, false, 0, ErrTruncated
	}

	// X.690 (02/2021) §8.1.3: keep the definite length unsigned until it
	// has been checked against the host's slice-index range.
	var decoded uint64
	for i := 1; i <= numBytes; i++ {
		decoded = decoded<<8 | uint64(data[i])
	}
	if decoded > uint64(math.MaxInt) {
		return 0, false, 0, fmt.Errorf("%w: length %d exceeds host int", ErrInvalidLength, decoded)
	}
	return int(decoded), false, 1 + numBytes, nil
}

// DecodeTLV reads one complete TLV element from data.
// Returns the tag, bytes consumed, and the value bytes.
func DecodeTLV(data []byte, options ...DecodeOption) (tag.Tag, int, []byte, error) {
	limits, limitErr := decodeLimits(options)
	if limitErr != nil {
		return tag.Tag{}, 0, nil, limitErr
	}
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}

	length, indefinite, lenLen, err := DecodeLength(data[tagLen:])
	if err != nil {
		return tag.Tag{}, 0, nil, err
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
			if pos-headerLen > limits.MaxWork || elements > limits.MaxElements {
				return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER scan work limit exceeded", ErrInvalidValue)
			}
			if len(data)-pos < 2 {
				return tag.Tag{}, 0, nil, ErrTruncated
			}
			if data[pos] == 0x00 && data[pos+1] == 0x00 {
				if depth == 0 {
					value := data[headerLen:pos]
					return t, pos + 2, value, nil
				}
				depth--
				pos += 2
				continue
			}
			// Skip nested TLVs.
			elements++
			_, innerTagLen, err := DecodeTag(data[pos:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			innerLen, innerIndef, innerLenLen, err := DecodeLength(data[pos+innerTagLen:])
			if err != nil {
				return tag.Tag{}, 0, nil, err
			}
			start := pos + innerTagLen + innerLenLen
			if innerIndef {
				depth++
				if depth > limits.MaxDepth {
					return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
				}
				pos = start
			} else {
				if innerLen > len(data)-start {
					return tag.Tag{}, 0, nil, ErrTruncated
				}
				pos = start + innerLen
			}
		}
	}

	if length > len(data)-headerLen {
		return tag.Tag{}, 0, nil, ErrTruncated
	}
	end := headerLen + length
	if end > limits.MaxWork {
		return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER total-work limit exceeded", ErrInvalidValue)
	}

	return t, end, data[headerLen:end], nil
}

// ValidateDERElement verifies that data contains exactly one DER TLV.
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
func ValidateDERTLV(data []byte) (int, error) {
	return validateDERTLV(data, 0, DefaultDecodeLimits().MaxDepth)
}

// ValidateDEREncodedElement validates a caller-supplied encoding without
// imposing the depth budget used when examining untrusted DER input.
func ValidateDEREncodedElement(data []byte) error {
	n, err := validateDERTLV(data, 0, len(data))
	if err != nil {
		return err
	}
	if n != len(data) {
		return ErrExtraData
	}
	return nil
}

func validateDERTLV(data []byte, depth, maxDepth int) (int, error) {
	if depth > maxDepth {
		return 0, fmt.Errorf("%w: DER nesting depth exceeded", ErrInvalidValue)
	}
	t, tagLen, err := DecodeTag(data)
	if err != nil {
		return 0, err
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
	if t.Constructed {
		// SET and SET OF have the same universal tag but different DER
		// ordering rules (X.690 10.3 and 11.6). Only a schema-aware caller
		// can validate that ordering; this generic pass validates each child.
		offset := headerLen
		for offset < end {
			n, err := validateDERTLV(data[offset:end], depth+1, maxDepth)
			if err != nil {
				return 0, err
			}
			offset += n
		}
	}
	return end, nil
}

// validateDERUniversalValue applies rules that do not require a schema.
// X.690 (02/2021) §§8.1.5, 8.2–8.4, 8.6, 8.8–8.12, 10.2,
// 11.1–11.2 and 11.7–11.8, including §8.19–8.20 subidentifier forms;
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
		tag.TagRelativeOID, tag.TagReal, tag.TagUTCTime, tag.TagGeneralizedTime:
		primitive = true
	case tag.TagBitString, tag.TagOctetString, tag.TagObjectDesc, tag.TagUTF8String,
		tag.TagNumericString, tag.TagPrintableString, tag.TagT61String, tag.TagVideotexString,
		tag.TagIA5String, tag.TagGraphicString, tag.TagVisibleString, tag.TagGeneralString,
		tag.TagUniversalString, tag.TagBMPString:
		primitive = true
	case tag.TagSequence, tag.TagSet, tag.TagExternal, tag.TagEmbeddedPDV:
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
		if len(value) != 13 || value[12] != 'Z' {
			return invalid("UTCTime requires YYMMDDhhmmssZ")
		}
		if _, err := parseUTCTime(string(value)); err != nil {
			return invalid("invalid UTCTime")
		}
	case tag.TagGeneralizedTime:
		if err := validateDERGeneralizedTime(value); err != nil {
			return invalid(err.Error())
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
		right, rightLen, rightValue, err := DecodeTLV(contents[used:], encodingStructureOption(contents[used:]))
		if err != nil {
			return err
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
	dataTag, dataLen, _, err := DecodeTLV(value[n:], encodingStructureOption(value[n:]))
	if err != nil {
		return err
	}
	if n+dataLen != len(value) || dataTag.Class != tag.ClassContextSpecific || dataTag.Number != 2 || dataTag.Constructed {
		return fmt.Errorf("EMBEDDED PDV requires one primitive [2] data-value")
	}
	return nil
}

// validateBase128Subidentifiers checks only X.690 (02/2021) §§8.19–8.20
// syntax. DER has no uint64 arc bound; typed []uint64 decoding does.
func validateBase128Subidentifiers(value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("empty subidentifier list")
	}
	for offset := 0; offset < len(value); {
		start := offset
		for {
			if offset >= len(value) {
				return fmt.Errorf("unterminated subidentifier")
			}
			b := value[offset]
			offset++
			if offset == start+1 && b == 0x80 {
				return fmt.Errorf("nonminimal subidentifier")
			}
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
	choice, _, err := DecodeTag(children[len(children)-1])
	if err != nil {
		return err
	}
	if choice.Constructed && choice.Number != 0 {
		return fmt.Errorf("EXTERNAL DER encoding choice must be primitive")
	}
	if decoded.Encoding == runtime.ExternalArbitrary {
		bits := decoded.Arbitrary
		unused := (8 - bits.BitLength%8) % 8
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

func validateDERGeneralizedTime(value []byte) error {
	if len(value) < 15 || value[len(value)-1] != 'Z' {
		return fmt.Errorf("GeneralizedTime requires YYYYMMDDhhmmssZ")
	}
	if _, err := time.Parse("20060102150405Z", string(value[:14])+"Z"); err != nil {
		return fmt.Errorf("invalid GeneralizedTime date")
	}
	if len(value) == 15 {
		return nil
	}
	if value[14] != '.' || len(value) < 17 || value[len(value)-2] == '0' {
		return fmt.Errorf("noncanonical GeneralizedTime fraction")
	}
	for _, digit := range value[15 : len(value)-1] {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("invalid GeneralizedTime fraction")
		}
	}
	return nil
}

func compareDEROctetStrings(left, right []byte) int {
	length := max(len(left), len(right))
	for index := 0; index < length; index++ {
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
		return nil, fmt.Errorf("%w: BER total-work limit exceeded", ErrInvalidValue)
	}
	var children [][]byte
	offset := 0
	for offset < len(data) {
		if len(children) >= limits.MaxElements {
			return nil, fmt.Errorf("%w: BER element limit exceeded", ErrInvalidValue)
		}
		t, total, value, err := DecodeTLV(data[offset:], options...)
		if err != nil {
			return nil, fmt.Errorf("at offset %d: %w", offset, err)
		}
		_ = t
		_ = value
		children = append(children, data[offset:offset+total])
		offset += total
	}
	return children, nil
}

// DecodeBoolean decodes a boolean from raw TLV bytes.
// Returns (value, rawByte, totalConsumed, error).
func DecodeBoolean(data []byte, options ...DecodeOption) (bool, byte, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return false, 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagBoolean {
		return false, 0, 0, fmt.Errorf("%w: expected BOOLEAN tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return false, 0, 0, fmt.Errorf("%w: BOOLEAN must be primitive, got constructed", ErrInvalidTag)
	}
	if len(value) != 1 {
		return false, 0, 0, fmt.Errorf("%w: BOOLEAN value must be 1 byte, got %d", ErrInvalidValue, len(value))
	}
	return value[0] != 0, value[0], total, nil
}

// DecodeInteger decodes an integer from raw TLV bytes.
func DecodeInteger(data []byte, options ...DecodeOption) (int64, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagInteger {
		return 0, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", ErrInvalidTag, t)
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
	if len(b) == 0 {
		return 0, fmt.Errorf("%w: empty integer", ErrInvalidValue)
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
		return nil, 0, fmt.Errorf("%w: expected INTEGER tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: INTEGER must be primitive, got constructed", ErrInvalidTag)
	}
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: INTEGER value must have at least 1 byte", ErrInvalidValue)
	}

	v := new(big.Int)
	if value[0]&0x80 != 0 {
		// Negative: convert two's complement.
		notBytes := make([]byte, len(value))
		for i, b := range value {
			notBytes[i] = ^b
		}
		v.SetBytes(notBytes)
		v.Add(v, big.NewInt(1))
		v.Neg(v)
	} else {
		v.SetBytes(value)
	}
	return v, total, nil
}

// DecodeBitString decodes a bit string from raw TLV bytes.
// Returns the bytes, unused bits count, and total bytes consumed.
func DecodeBitString(data []byte, options ...DecodeOption) ([]byte, int, int, error) {
	limits, err := decodeLimits(options)
	if err != nil {
		return nil, 0, 0, err
	}
	return decodeBitStringBounded(data, 0, &berWorkBudget{limits: limits})
}

func decodeBitStringBounded(data []byte, depth int, budget *berWorkBudget) ([]byte, int, int, error) {
	if depth > budget.limits.MaxDepth {
		return nil, 0, 0, fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
	}
	t, total, value, err := DecodeTLV(data, WithDecodeLimits(budget.limits))
	if err != nil {
		return nil, 0, 0, err
	}
	if err := budget.charge(total); err != nil {
		return nil, 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagBitString {
		return nil, 0, 0, fmt.Errorf("%w: expected BIT STRING tag, got %s", ErrInvalidTag, t)
	}
	decoded, unusedBits, err := decodeBitStringValueBounded(t.Constructed, value, depth, budget)
	return decoded, unusedBits, total, err
}

// DecodeOctetString decodes an octet string from raw TLV bytes.
func DecodeOctetString(data []byte, options ...DecodeOption) ([]byte, int, error) {
	limits, err := decodeLimits(options)
	if err != nil {
		return nil, 0, err
	}
	return decodeOctetStringBounded(data, 0, &berWorkBudget{limits: limits})
}

func decodeOctetStringBounded(data []byte, depth int, budget *berWorkBudget) ([]byte, int, error) {
	if depth > budget.limits.MaxDepth {
		return nil, 0, fmt.Errorf("%w: BER nesting depth exceeded", ErrInvalidValue)
	}
	t, total, value, err := DecodeTLV(data, WithDecodeLimits(budget.limits))
	if err != nil {
		return nil, 0, err
	}
	if err := budget.charge(total); err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagOctetString {
		return nil, 0, fmt.Errorf("%w: expected OCTET STRING tag, got %s", ErrInvalidTag, t)
	}
	// Handle constructed form (BER allows it).
	if t.Constructed {
		var result []byte
		for offset := 0; offset < len(value); {
			childVal, consumed, err := decodeOctetStringBounded(value[offset:], depth+1, budget)
			if err != nil {
				return nil, 0, err
			}
			result = append(result, childVal...)
			offset += consumed
		}
		return result, total, nil
	}
	return value, total, nil
}

// DecodeNull decodes a NULL from raw TLV bytes.
func DecodeNull(data []byte, options ...DecodeOption) (int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagNull {
		return 0, fmt.Errorf("%w: expected NULL tag, got %s", ErrInvalidTag, t)
	}
	if len(value) != 0 {
		return 0, fmt.Errorf("%w: NULL value must be empty, got %d bytes", ErrInvalidValue, len(value))
	}
	return total, nil
}

// DecodeObjectIdentifier decodes an OID from raw TLV bytes.
func DecodeObjectIdentifier(data []byte, options ...DecodeOption) ([]uint64, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagObjectID {
		return nil, 0, fmt.Errorf("%w: expected OBJECT IDENTIFIER tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: OBJECT IDENTIFIER must be primitive", ErrInvalidTag)
	}
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: OBJECT IDENTIFIER content must contain at least one subidentifier", ErrInvalidValue)
	}

	// Decode first two components.
	firstVal, offset, err := decodeBase128(value, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding OID first subidentifier: %w", err)
	}
	var oid []uint64
	if firstVal < 80 {
		oid = append(oid, firstVal/40, firstVal%40)
	} else {
		oid = append(oid, 2, firstVal-80)
	}

	// Decode remaining components.
	for offset < len(value) {
		v, newOffset, err := decodeBase128(value, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding OID subidentifier: %w", err)
		}
		oid = append(oid, v)
		offset = newOffset
	}

	return oid, total, nil
}

// DecodeRelativeObjectIdentifier decodes a RELATIVE-OID per X.690
// (02/2021) section 8.20.
func DecodeRelativeObjectIdentifier(data []byte, options ...DecodeOption) ([]uint64, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagRelativeOID {
		return nil, 0, fmt.Errorf("%w: expected RELATIVE-OID tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return nil, 0, fmt.Errorf("%w: RELATIVE-OID must be primitive", ErrInvalidTag)
	}
	oid, err := DecodeRelativeOIDValue(value)
	if err != nil {
		return nil, 0, err
	}
	return oid, total, nil
}

func decodeBase128(data []byte, offset int) (uint64, int, error) {
	var v uint64
	start := offset
	for offset < len(data) {
		b := data[offset]
		offset++
		if offset == start+1 && b == 0x80 && offset < len(data) {
			return 0, offset, fmt.Errorf("%w: non-minimal base-128 subidentifier", ErrInvalidValue)
		}
		bits := uint64(b & 0x7f)
		if v > math.MaxUint64>>7 || v == math.MaxUint64>>7 && bits > math.MaxUint64&0x7f {
			return 0, offset, fmt.Errorf("%w: base-128 subidentifier overflows uint64", ErrInvalidValue)
		}
		v = (v << 7) | bits
		if b&0x80 == 0 {
			return v, offset, nil
		}
	}
	if offset == start {
		return 0, offset, fmt.Errorf("%w: empty base-128 encoding", ErrInvalidValue)
	}
	return 0, offset, fmt.Errorf("%w: truncated base-128 encoding", ErrTruncated)
}

// DecodeEnumerated decodes an ENUMERATED value from raw TLV bytes.
func DecodeEnumerated(data []byte, options ...DecodeOption) (int64, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return 0, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagEnumerated {
		return 0, 0, fmt.Errorf("%w: expected ENUMERATED tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return 0, 0, fmt.Errorf("%w: ENUMERATED must be primitive, got constructed", ErrInvalidTag)
	}
	if len(value) == 0 {
		return 0, 0, fmt.Errorf("%w: ENUMERATED value must have at least 1 byte", ErrInvalidValue)
	}
	v, err := decodeIntBytes(value)
	if err != nil {
		return 0, 0, err
	}
	return v, total, nil
}

// DecodeReal decodes an exact REAL value from raw TLV bytes per ITU-T X.690
// (02/2021), clause 8.5. Decimal NR1, NR2, and NR3 forms follow clause 8.5.8
// and ISO 6093:1985.
func DecodeReal(data []byte, options ...DecodeOption) (runtime.Real, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return runtime.Real{}, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagReal {
		return runtime.Real{}, 0, fmt.Errorf("%w: expected REAL tag, got %s", ErrInvalidTag, t)
	}
	if t.Constructed {
		return runtime.Real{}, 0, fmt.Errorf("%w: REAL must be primitive", ErrInvalidTag)
	}
	decoded, err := decodeRealContents(value)
	if err != nil {
		return runtime.Real{}, 0, err
	}
	return decoded, total, nil
}

// DecodeString decodes a string type (UTF8, IA5, PrintableString, etc.) from raw TLV bytes.
// The caller provides the expected tag number.
func DecodeString(data []byte, expectedTag int, options ...DecodeOption) (string, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return "", 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != expectedTag {
		return "", 0, fmt.Errorf("%w: expected tag %d, got %s", ErrInvalidTag, expectedTag, t)
	}
	if t.Constructed {
		// X.690 (02/2021) 8.23.3 defines a restricted character string as
		// an implicitly tagged OCTET STRING, so constructed values contain
		// OCTET STRING fragments rather than repetitions of the outer tag.
		var encoded []byte
		for offset := 0; offset < len(value); {
			part, consumed, err := DecodeOctetString(value[offset:], options...)
			if err != nil {
				return "", 0, fmt.Errorf("decoding constructed string component: %w", err)
			}
			if consumed <= 0 {
				return "", 0, fmt.Errorf("%w: constructed string component consumed no input", ErrInvalidValue)
			}
			encoded = append(encoded, part...)
			offset += consumed
		}
		decoded, err := DecodeStringValueTag(expectedTag, encoded)
		if err != nil {
			return "", 0, err
		}
		return decoded, total, nil
	}
	decoded, err := DecodeStringValueTag(expectedTag, value)
	if err != nil {
		return "", 0, err
	}
	return decoded, total, nil
}

// DecodeUTCTime decodes a UTCTime value from raw TLV bytes.
func DecodeUTCTime(data []byte, options ...DecodeOption) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagUTCTime, options...)
	if err != nil {
		return time.Time{}, 0, err
	}
	t, err := parseUTCTime(s)
	if err != nil {
		return time.Time{}, 0, err
	}
	return t, total, nil
}

// DecodeGeneralizedTime decodes a GeneralizedTime value from raw TLV bytes.
func DecodeGeneralizedTime(data []byte, options ...DecodeOption) (time.Time, int, error) {
	s, total, err := DecodeString(data, tag.TagGeneralizedTime, options...)
	if err != nil {
		return time.Time{}, 0, err
	}
	t, err := parseGeneralizedTime(s)
	if err != nil {
		return time.Time{}, 0, err
	}
	return t, total, nil
}

// DecodeUTCTimeValue decodes a UTCTime from raw value bytes (tag/length
// already consumed by the caller — e.g. an implicitly tagged field, where
// the wrapping tag replaced the UNIVERSAL UTCTime tag, or a CHOICE
// alternative whose tag has already been matched).
func DecodeUTCTimeValue(value []byte) (time.Time, error) {
	return parseUTCTime(string(value))
}

// DecodeGeneralizedTimeValue decodes a GeneralizedTime from raw value bytes
// (tag/length already consumed by the caller — see DecodeUTCTimeValue).
func DecodeGeneralizedTimeValue(value []byte) (time.Time, error) {
	return parseGeneralizedTime(string(value))
}

// parseUTCTime parses the character content of an ASN.1 UTCTime.
func parseUTCTime(s string) (time.Time, error) {
	// Try common formats.
	for _, layout := range []string{
		"060102150405Z",
		"0601021504Z",
		"060102150405-0700",
		"060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			// ASN.1 UTCTime: YY >= 50 → 19YY, YY < 50 → 20YY.
			// Go's time.Parse uses cutoff 69, so years 50-68 are wrong.
			year := t.Year()
			if year >= 2050 && year <= 2068 {
				t = t.AddDate(-100, 0, 0)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: cannot parse UTCTime %q", ErrInvalidValue, s)
}

// parseGeneralizedTime parses the character content of an ASN.1 GeneralizedTime.
func parseGeneralizedTime(s string) (time.Time, error) {
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405",
		"20060102150405.000Z",
		"20060102150405-0700",
		"20060102150405+0700",
	} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: cannot parse GeneralizedTime %q", ErrInvalidValue, s)
}

// DecodeRawValue reads one complete TLV without interpreting the value.
// Returns the tag, raw value bytes, and total bytes consumed.
func DecodeRawValue(data []byte, options ...DecodeOption) (tag.Tag, []byte, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return tag.Tag{}, nil, 0, err
	}
	return t, value, total, nil
}

// PeekTag reads the tag from data without consuming it.
func PeekTag(data []byte) (tag.Tag, error) {
	t, _, err := DecodeTag(data)
	return t, err
}

// --- Value-level decoders for generated code ---
// These decode from raw value bytes (tag+length already consumed).

// DecodeIntegerValue decodes an integer from raw value bytes.
func DecodeIntegerValue(value []byte) (int64, error) {
	return decodeIntBytes(value)
}

// DecodeEnumeratedValue decodes primitive ENUMERATED contents after its tag
// and length have been consumed by an implicit-tag decoder.
func DecodeEnumeratedValue(value []byte) (int64, error) {
	return decodeIntBytes(value)
}

// DecodeBooleanValue decodes a boolean from raw value bytes.
func DecodeBooleanValue(value []byte) (bool, error) {
	if len(value) != 1 {
		return false, fmt.Errorf("%w: BOOLEAN value must be 1 byte, got %d", ErrInvalidValue, len(value))
	}
	return value[0] != 0, nil
}

// DecodeBitStringValue decodes a bit string from raw value bytes.
func DecodeBitStringValue(value []byte) ([]byte, int, error) {
	return decodePrimitiveBitStringValue(value)
}

// DecodeImplicitBitStringValue decodes primitive or constructed BIT STRING
// contents after an implicit tag has been consumed. X.690 (02/2021) 8.6.1
// permits both forms and 8.6.4.1 requires recursive, ordered segments.
func DecodeImplicitBitStringValue(constructed bool, value []byte, options ...DecodeOption) ([]byte, int, error) {
	return decodeBitStringValue(constructed, value, options...)
}

func decodeBitStringValue(constructed bool, value []byte, options ...DecodeOption) ([]byte, int, error) {
	limits, err := decodeLimits(options)
	if err != nil {
		return nil, 0, err
	}
	budget := &berWorkBudget{limits: limits}
	if err := budget.charge(len(value)); err != nil {
		return nil, 0, err
	}
	return decodeBitStringValueBounded(constructed, value, 0, budget)
}

func decodeBitStringValueBounded(constructed bool, value []byte, depth int, budget *berWorkBudget) ([]byte, int, error) {
	if !constructed {
		return decodePrimitiveBitStringValue(value)
	}
	var result []byte
	unusedBits := 0
	for index, offset := 0, 0; offset < len(value); index++ {
		segment, segmentUnused, consumed, err := decodeBitStringBounded(value[offset:], depth+1, budget)
		if err != nil {
			return nil, 0, fmt.Errorf("decoding constructed BIT STRING segment %d: %w", index, err)
		}
		if offset+consumed < len(value) && segmentUnused != 0 {
			return nil, 0, fmt.Errorf("%w: BIT STRING segment %d has %d unused bits before the final segment", ErrInvalidValue, index, segmentUnused)
		}
		result = append(result, segment...)
		unusedBits = segmentUnused
		offset += consumed
	}
	return result, unusedBits, nil
}

func decodePrimitiveBitStringValue(value []byte) ([]byte, int, error) {
	if len(value) == 0 {
		return nil, 0, fmt.Errorf("%w: empty BIT STRING value", ErrInvalidValue)
	}
	unusedBits := int(value[0])
	if unusedBits > 7 {
		return nil, 0, fmt.Errorf("%w: BIT STRING unused bits %d out of range (0-7)", ErrInvalidValue, unusedBits)
	}
	if len(value) == 1 && unusedBits != 0 {
		return nil, 0, fmt.Errorf("%w: BIT STRING unused bits %d with no content bytes", ErrInvalidValue, unusedBits)
	}
	return value[1:], unusedBits, nil
}

// DecodeStringValue returns raw value bytes as a string.
func DecodeStringValue(value []byte) string {
	return string(value)
}

// DecodeStringValueTag decodes restricted-character-string contents according
// to the supplied UNIVERSAL tag number. X.690 (02/2021) sections 8.23.7 and
// 8.23.8 require four-octet UniversalString and two-octet BMPString forms.
func DecodeStringValueTag(tagNum int, value []byte) (string, error) {
	switch tagNum {
	case tag.TagBMPString:
		if len(value)%2 != 0 {
			return "", fmt.Errorf("%w: BMPString content length %d is not divisible by 2", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/2)
		for offset := 0; offset < len(value); offset += 2 {
			r := rune(binary.BigEndian.Uint16(value[offset : offset+2]))
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: BMPString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
		}
		return string(runes), nil
	case tag.TagUniversalString:
		if len(value)%4 != 0 {
			return "", fmt.Errorf("%w: UniversalString content length %d is not divisible by 4", ErrInvalidValue, len(value))
		}
		runes := make([]rune, 0, len(value)/4)
		for offset := 0; offset < len(value); offset += 4 {
			r := rune(binary.BigEndian.Uint32(value[offset : offset+4]))
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("%w: UniversalString contains invalid code point U+%04X", ErrInvalidValue, r)
			}
			runes = append(runes, r)
		}
		return string(runes), nil
	default:
		return string(value), nil
	}
}

// DecodeImplicitStringValue decodes the contents of an implicitly tagged
// restricted character string while preserving BER's primitive or constructed form.
func DecodeImplicitStringValue(tagNum int, constructed bool, value []byte, options ...DecodeOption) (string, error) {
	if !constructed {
		return DecodeStringValueTag(tagNum, value)
	}
	reconstructed := EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: tagNum}, value)
	decoded, total, err := DecodeString(reconstructed, tagNum, options...)
	if err != nil {
		return "", err
	}
	if total != len(reconstructed) {
		return "", ErrExtraData
	}
	return decoded, nil
}

// DecodeImplicitUTCTimeValue decodes primitive or constructed implicitly tagged UTCTime contents.
func DecodeImplicitUTCTimeValue(constructed bool, value []byte, options ...DecodeOption) (time.Time, error) {
	decoded, err := DecodeImplicitStringValue(tag.TagUTCTime, constructed, value, options...)
	if err != nil {
		return time.Time{}, err
	}
	return parseUTCTime(decoded)
}

// DecodeImplicitGeneralizedTimeValue decodes primitive or constructed implicitly tagged GeneralizedTime contents.
func DecodeImplicitGeneralizedTimeValue(constructed bool, value []byte, options ...DecodeOption) (time.Time, error) {
	decoded, err := DecodeImplicitStringValue(tag.TagGeneralizedTime, constructed, value, options...)
	if err != nil {
		return time.Time{}, err
	}
	return parseGeneralizedTime(decoded)
}

// DecodeRealValue decodes X.690 (02/2021), clause 8.5 REAL contents octets.
func DecodeRealValue(value []byte) (runtime.Real, error) {
	return decodeRealContents(value)
}

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
	scaleFactor := int64((info >> 2) & 0x03)
	expLen := int(info&0x03) + 1
	offset := 1
	if info&0x03 == 3 {
		if offset >= len(value) {
			return runtime.Real{}, fmt.Errorf("%w: REAL exponent length truncated", ErrTruncated)
		}
		expLen = int(value[offset])
		offset++
		if expLen == 0 {
			return runtime.Real{}, fmt.Errorf("%w: REAL exponent length is zero", ErrInvalidValue)
		}
	}
	if offset+expLen >= len(value) {
		return runtime.Real{}, fmt.Errorf("%w: REAL exponent or mantissa truncated", ErrTruncated)
	}
	exponentBytes := value[offset : offset+expLen]
	if info&0x03 == 3 && len(exponentBytes) > 1 &&
		(exponentBytes[0] == 0x00 && exponentBytes[1]&0x80 == 0 || exponentBytes[0] == 0xff && exponentBytes[1]&0x80 != 0) {
		return runtime.Real{}, fmt.Errorf("%w: REAL long exponent violates the first-nine-bits rule", ErrInvalidValue)
	}
	exponent, err := DecodeBigIntValue(exponentBytes)
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
		if mark < 0 {
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
			if exponentMark < 0 {
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
func DecodeOIDValue(value []byte) ([]uint64, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty OID value", ErrInvalidValue)
	}
	result := make([]uint64, 0, 8)
	first, offset, err := decodeBase128(value, 0)
	if err != nil {
		return nil, fmt.Errorf("decoding OID first subidentifier: %w", err)
	}
	if first >= 80 {
		result = append(result, 2, first-80)
	} else {
		result = append(result, first/40, first%40)
	}
	for offset < len(value) {
		v, consumed, err := decodeBase128(value, offset)
		if err != nil {
			return nil, fmt.Errorf("decoding OID subidentifier: %w", err)
		}
		result = append(result, v)
		offset = consumed
	}
	return result, nil
}

// DecodeRelativeOIDValue decodes X.690 section 8.20 contents octets.
func DecodeRelativeOIDValue(value []byte) ([]uint64, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty RELATIVE-OID value", ErrInvalidValue)
	}
	oid := make([]uint64, 0, 4)
	for offset := 0; offset < len(value); {
		arc, next, err := decodeBase128(value, offset)
		if err != nil {
			return nil, fmt.Errorf("decoding RELATIVE-OID subidentifier: %w", err)
		}
		oid = append(oid, arc)
		offset = next
	}
	return oid, nil
}

// SkipTLV skips one complete TLV in data and returns the number of bytes consumed.
func SkipTLV(data []byte, options ...DecodeOption) (int, error) {
	_, total, _, err := DecodeTLV(data, options...)
	return total, err
}

// DecodeSequenceContent decodes the outer SEQUENCE tag and returns the content bytes
// and total bytes consumed. This is used by generated UnmarshalBER methods.
func DecodeSequenceContent(data []byte, options ...DecodeOption) ([]byte, int, error) {
	t, total, value, err := DecodeTLV(data, options...)
	if err != nil {
		return nil, 0, err
	}
	if t.Class != tag.ClassUniversal || t.Number != tag.TagSequence || !t.Constructed {
		return nil, 0, fmt.Errorf("%w: expected SEQUENCE, got %s", ErrInvalidTag, t)
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
	if len(value) == 0 {
		return nil, fmt.Errorf("%w: empty integer", ErrInvalidValue)
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
