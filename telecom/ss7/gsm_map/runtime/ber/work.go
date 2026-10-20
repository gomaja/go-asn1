// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/work.go; SHA-256 f20463d830cec46c327863ef5146a953dd8e7d829dcd8e0652967339789ebbc8.
package ber

import (
	"bytes"
	"fmt"
	"unicode/utf8"
	"weak"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

type berScanFrame struct {
	end           int
	indefinite    bool
	segmentTag    int
	unusedBits    int
	segmentOffset int
	segmentIndex  int
	utf8Contents  *[]byte
	utf8Root      bool
	utf8Source    *byte
	offset        int
	index         int
	nextChild     int
}

// ValidateBEREncodedElement checks that caller-supplied open-type bytes hold
// exactly one complete value. An end-of-contents marker is not a value.
// Encoding uses input-sized limits so a decoded value can be emitted again.
// ITU-T X.690 (02/2021) §§8.1.5, 8.15.
func ValidateBEREncodedElement(data []byte) error {
	return ValidateBERElement(data, encodingStructureOption(data))
}

// ValidateBERElement checks exactly one complete BER value, including universal
// contents and recursive string segment rules, with a single linear scan.
// X.690 (02/2021) §§8.1.3 and 8.7 permit indefinite constructed values;
// the limits are operational safeguards, not restrictions in X.690.
// Wire failures wrap their original cause in an ElementError; invalid options
// are rejected before input inspection and have no element location.
// Tolerant preflight also reports malformed opaque strings. A later typed
// decoder qualifies the same report with its schema path instead of duplicating it.
func ValidateBERElement(data []byte, options ...DecodeOption) (returnErr error) {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	// TS 29.002 V19.1.0 §17.1.1 applies only to MAP-defined content.
	// A standalone BER walk cannot identify foreign open values (X.690
	// (02/2021) §8.15), so require a generated typed decoder to claim them.
	if config.form != nil && config.form.mapSyntax == mapSyntaxProfile {
		return fmt.Errorf("%w: MAP profile requires a generated MAP decoder", ErrInvalidValue)
	}
	// An unknown CHOICE alternative is a complete foreign encoding, including
	// its identifier and length (X.690 (02/2021) §8.15; TS 29.002 §17.1.1).
	if len(options) == 1 {
		if child, ok := options[0].(*generatedDecodeOption); ok && child.component == "UnknownExtension" {
			excludeMAPOpaque(config, data, len(data))
		}
	}
	if config.form != nil && config.generatedMode == generatedModeProof && config.form.lightInput == nil {
		config.form.proofNeeded = true
	}
	var detachedContext *generatedDecodeOption
	if len(options) != 0 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil && context.source != nil && !context.source.light {
			if _, within := berSubsliceOffset(context.source.owned, data); within {
				if !context.source.validElement(data) {
					return fmt.Errorf("%w: generated BER child is not a validated element", ErrInvalidValue)
				}
				if len(options) == 1 && context.source.matchesValidated(data) {
					return nil
				}
			} else {
				detachedContext = context
			}
		}
	}
	probeOptions := options
	for _, option := range options {
		if _, diagnostic := option.(diagnosticChildOption); diagnostic {
			probeOptions = expandGeneratedDecodeOptions(options)
			break
		}
	}
	if len(probeOptions) != 0 {
		if probe, ok := probeOptions[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
			return nil
		}
	}
	limits := config.limits
	// A generated child can be rewrapped with a synthetic identifier. The
	// public-root scan already reports visible UTF8String octets under
	// X.690 (02/2021) §8.23.10, and the
	// typed decoder reports implicitly tagged strings. A second scan of the
	// detached wrapper has no reliable original-wire location to publish.
	reportUTF8 := true
	if config.tolerant && config.location != nil {
		_, reportUTF8 = berSubsliceOffset(config.location.origin.root, data)
	}

	var spans map[int]int
	var shortSpans []uint16
	if detachedContext != nil || config.form != nil && config.form.owned != nil && (len(options) == 0 || !isGeneratedDecodeContext(options[0])) {
		if len(data) <= 0xffff {
			shortSpans = make([]uint16, len(data))
		} else {
			spans = make(map[int]int)
		}
	}
	var initial [8]berScanFrame
	initial[0].end = len(data)
	stack := initial[:1]
	failureOffset, failureDepth, failureIndex := 0, 1, 0
	defer func() {
		if returnErr == nil {
			return
		}
		var indexes []int
		if failureDepth > 1 {
			// The sentinel and root frames have no child position in the path.
			for _, ancestor := range stack[2:failureDepth] {
				indexes = append(indexes, ancestor.index)
			}
			indexes = append(indexes, failureIndex)
		}
		if config.location != nil {
			if absolute, ok := config.location.wireOffset(data[failureOffset:]); ok {
				failureOffset = absolute
				indexes, _ = config.location.origin.ancestry(absolute)
			} else {
				base := config.location.receivedOffset()
				if found, ok := config.location.origin.mark(qualifyConstraintPath(options, "")); ok {
					base = found
				}
				if failureOffset <= len(config.location.origin.root)-base {
					failureOffset += base
					indexes, _ = config.location.origin.ancestry(failureOffset)
				}
			}
		}
		returnErr = &ElementError{offset: failureOffset, childIndexes: indexes, cause: returnErr}
	}()
	if len(data) == 0 {
		return ErrTruncated
	}

	pos, elements, work := 0, 0, 0
	// An ancestry search suspends immediately before its target identifier.
	// Increasing targets resume the same bounded pass; repeated targets are
	// served by decodeOrigin's record cache. A backwards uncached lookup
	// restarts its path but retains the work already charged.
	if search := config.positionSearch; search != nil {
		work = search.work
		if search.stack != nil && search.target >= search.pos {
			stack, pos, elements = append(initial[:0], search.stack...), search.pos, search.elements
		}
		defer func() {
			search.stack, search.pos, search.elements, search.work = append(search.stack[:0], stack...), pos, elements, work
		}()
	}
	// X.690 (02/2021) §8.6.4.1: the final nested segment supplies
	// the unused-bit count of its containing BIT STRING segment.
	closeFrame := func() error {
		if len(stack) == 0 {
			return ErrInvalidLength
		}
		closed := stack[len(stack)-1]
		if len(stack) > 1 {
			if shortSpans != nil {
				shortSpans[closed.offset] = uint16(pos)
			} else if spans != nil {
				spans[closed.offset] = pos
			}
		}
		failureOffset, failureDepth, failureIndex = closed.offset, len(stack)-1, closed.index
		if closed.utf8Root && reportUTF8 && !utf8.Valid(*closed.utf8Contents) {
			position, err := scannedUTF8Location(data, closed.offset, stack[:len(stack)-1], closed.index, config, options)
			if err != nil {
				return err
			}
			if err := checkUTF8String(*closed.utf8Contents, closed.utf8Source, config, options, true, &position); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		if len(stack) != 0 && stack[len(stack)-1].segmentTag == tag.TagBitString {
			stack[len(stack)-1].unusedBits = closed.unusedBits
			stack[len(stack)-1].segmentOffset = closed.offset
			stack[len(stack)-1].segmentIndex = closed.index
		}
		return nil
	}
	for len(stack) != 0 {
		parent := stack[len(stack)-1]
		failureOffset, failureDepth, failureIndex = pos, len(stack), parent.nextChild
		if pos == parent.end {
			if parent.indefinite {
				failureOffset, failureDepth, failureIndex = parent.offset, len(stack)-1, parent.index
				return ErrTruncated
			}
			if err := closeFrame(); err != nil {
				return err
			}
			continue
		}
		if pos < 0 || pos > parent.end {
			return ErrInvalidLength
		}
		if len(stack) == 1 && elements > 0 {
			return ErrExtraData
		}
		if parent.indefinite && parent.end-pos >= 2 && data[pos] == 0 && data[pos+1] == 0 {
			if 2 > limits.MaxWork-work {
				failureOffset, failureDepth, failureIndex = parent.offset, len(stack)-1, parent.index
				return fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
			}
			work += 2
			pos += 2
			if err := closeFrame(); err != nil {
				return err
			}
			continue
		}
		if search := config.positionSearch; search != nil && pos >= search.target {
			if pos == search.target && len(stack) > 1 {
				for _, ancestor := range stack[2:] {
					search.indexes = append(search.indexes, ancestor.index)
				}
				search.indexes = append(search.indexes, parent.nextChild)
			}
			return nil
		}
		if parent.segmentTag == tag.TagBitString && parent.unusedBits != 0 {
			// X.690 (02/2021) §8.6.4: the previous segment, rather
			// than the next identifier, violates the octet-alignment rule.
			failureOffset, failureIndex = parent.segmentOffset, parent.segmentIndex
			return fmt.Errorf("%w: non-final BIT STRING segment has unused bits", ErrInvalidValue)
		}
		if search := config.positionSearch; search != nil && search.visits != nil {
			(*search.visits)++
		}
		t, tagLen, err := DecodeTag(data[pos:parent.end])
		if err != nil {
			return err
		}
		if tagLen < 0 || tagLen > parent.end-pos {
			return ErrInvalidLength
		}
		length, indefinite, lenLen, err := DecodeLength(data[pos+tagLen : parent.end])
		if err != nil {
			return err
		}
		if lenLen < 0 || lenLen > parent.end-pos-tagLen {
			return ErrInvalidLength
		}
		if t.Class == tag.ClassUniversal && t.Number == 0 {
			return fmt.Errorf("%w: standalone BER end-of-contents", ErrInvalidTag)
		}
		if parent.segmentTag != 0 && (t.Class != tag.ClassUniversal || t.Number != parent.segmentTag) {
			return fmt.Errorf("%w: expected universal string segment tag %d, got %s", ErrInvalidTag, parent.segmentTag, t)
		}
		// Charge a header and each primitive content octet exactly once as
		// the scan advances. A work refusal names this identifier (#155).
		charge := tagLen + lenLen
		if !t.Constructed && !indefinite {
			if length > parent.end-pos-charge {
				return ErrTruncated
			}
			charge += length
		}
		if charge > limits.MaxWork-work {
			return fmt.Errorf("%w: BER total-work limit exceeded", ErrResourceLimit)
		}
		work += charge
		// Checked before either length branch, so an indefinite length
		// cannot carry a constructed primitive-only type past it.
		if err := checkUniversalForm(t); err != nil {
			return err
		}
		if elements >= limits.MaxElements {
			return fmt.Errorf("%w: BER element limit exceeded", ErrResourceLimit)
		}
		elements++
		// Each counted child consumes an element, bounding this index by
		// the checked MaxElements budget above.
		stack[len(stack)-1].nextChild++
		start := pos + tagLen + lenLen
		var contents []byte
		if !indefinite && length <= parent.end-start {
			contents = data[start : start+length]
		}
		markBERForm(config.form, t, data[pos+tagLen:start], indefinite, contents)
		collectMAPForm(config.form, data, pos, t, data[pos+tagLen:start], indefinite)
		// X.690 (02/2021) §§8.23.3, 8.23.10: UTF-8 characters may span
		// OCTET STRING fragments. Share one bounded concatenation across
		// nested fragments and validate it when the UTF8String closes.
		utf8Contents := parent.utf8Contents
		utf8Source := parent.utf8Source
		utf8Root := !config.collectPositionsOnly && t.Constructed && t.Class == tag.ClassUniversal && t.Number == tag.TagUTF8String
		if utf8Root {
			utf8Contents = new([]byte)
			if start < len(data) {
				utf8Source = &data[start]
			}
		}

		if indefinite {
			if config.form != nil && config.form.lightInput == nil && config.generatedMode != generatedModeLight {
				config.form.proofNeeded = true
			}
			if !t.Constructed {
				return fmt.Errorf("%w: indefinite length used with primitive tag %s", ErrInvalidLength, t)
			}
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)
			}
			stack = append(stack, berScanFrame{end: parent.end, indefinite: true, segmentTag: berSegmentTag(t), utf8Contents: utf8Contents, utf8Root: utf8Root, utf8Source: utf8Source, offset: pos, index: parent.nextChild})
			pos = start
			continue
		}
		if start > parent.end {
			return ErrTruncated
		}
		if length > parent.end-start {
			return ErrTruncated
		}
		end := start + length
		if !t.Constructed && t.Class == tag.ClassUniversal {
			if t.Number == tag.TagUTF8String && !config.collectPositionsOnly {
				var source *byte
				if start < end {
					source = &data[start]
				}
				if reportUTF8 && !utf8.Valid(data[start:end]) {
					position, err := scannedUTF8Location(data, pos, stack, parent.nextChild, config, options)
					if err != nil {
						return err
					}
					if err := checkUTF8String(data[start:end], source, config, options, true, &position); err != nil {
						return err
					}
				}
			}
			if utf8Contents != nil {
				*utf8Contents = append(*utf8Contents, data[start:end]...)
			}
			if err := validateBERUniversalContents(t.Number, data[start:end]); err != nil {
				return err
			}
			if parent.segmentTag == tag.TagBitString {
				stack[len(stack)-1].unusedBits = int(data[start])
				stack[len(stack)-1].segmentOffset = pos
				stack[len(stack)-1].segmentIndex = parent.nextChild
			}
		}
		if t.Constructed {
			// A chain becomes cheaper with a proof after eight constructed
			// levels. Shallow definite values keep ordinary nested checks.
			if config.form != nil && config.form.lightInput == nil && config.generatedMode != generatedModeLight && len(stack) > 8 {
				config.form.proofNeeded = true
			}
			if len(stack) > limits.MaxDepth {
				return fmt.Errorf("%w: BER nesting depth exceeded", ErrResourceLimit)
			}
			stack = append(stack, berScanFrame{end: end, segmentTag: berSegmentTag(t), utf8Contents: utf8Contents, utf8Root: utf8Root, utf8Source: utf8Source, offset: pos, index: parent.nextChild})
			pos = start
		} else {
			if shortSpans != nil {
				shortSpans[pos] = uint16(end)
			} else if spans != nil {
				spans[pos] = end
			}
			pos = end
		}
	}
	if pos != len(data) {
		return ErrExtraData
	}
	if spans != nil || shortSpans != nil {
		validated := append([]byte(nil), data...)
		if detachedContext != nil {
			detachedContext.pending = &validatedBERSource{input: data, validated: validated, spans: spans, shortSpans: shortSpans, replay: detachedContext.source.replay}
		} else {
			config.form.validated = &validatedBERSource{input: data, validated: validated, spans: spans, shortSpans: shortSpans}
		}
	}
	return nil
}

// X.690 (02/2021) §§8.6.4.1, 8.7.3.2, 8.23.3: restricted
// character strings are implicitly tagged OCTET STRINGs; their segments
// retain universal tag 4, while BIT STRING segments retain tag 3.
func berSegmentTag(t tag.Tag) int {
	if t.Class != tag.ClassUniversal || !t.Constructed {
		return 0
	}
	switch t.Number {
	case tag.TagBitString:
		return tag.TagBitString
	case tag.TagOctetString, tag.TagObjectDesc, tag.TagUTF8String,
		tag.TagNumericString, tag.TagPrintableString, tag.TagT61String,
		tag.TagVideotexString, tag.TagIA5String, tag.TagGraphicString,
		tag.TagVisibleString, tag.TagGeneralString, tag.TagUniversalString,
		tag.TagBMPString, tag.TagUTCTime, tag.TagGeneralizedTime:
		return tag.TagOctetString
	}
	return 0
}

func validateBERUniversalContents(number int, contents []byte) error {
	// X.690 (02/2021) §§8.2.1, 8.3.2, 8.4, 8.6.2, 8.8.2,
	// 8.19.2, 8.20.2. BER permits non-ff TRUE and arbitrary unused bits.
	switch number {
	case tag.TagBoolean:
		if len(contents) != 1 {
			return fmt.Errorf("%w: BOOLEAN requires exactly one contents octet", ErrInvalidValue)
		}
	case tag.TagNull:
		if len(contents) != 0 {
			return fmt.Errorf("%w: NULL requires empty contents", ErrInvalidValue)
		}
	case tag.TagInteger, tag.TagEnumerated:
		return validateMinimalIntegerContents(contents)
	case tag.TagBitString:
		return validatePrimitiveBitStringContents(contents)
	case tag.TagObjectID, tag.TagRelativeOID:
		// Validate the base-128 spelling, without a uint64 arc ceiling.
		if err := validateBase128Subidentifiers(contents); err != nil {
			return fmt.Errorf("%w: universal tag %d: %s", ErrInvalidValue, number, err)
		}
	}
	return nil
}

// checkUniversalForm rejects a universal type in the form X.690 (02/2021)
// forbids for it. BOOLEAN (§8.2.1), INTEGER (§8.3.1), ENUMERATED (§8.4),
// REAL (§8.5.1), NULL (§8.8.1), OBJECT IDENTIFIER (§8.19.1), RELATIVE-OID
// (§8.20.1), the OID and relative OID IRI types (§§8.21.1, 8.22.1) and TIME,
// DATE, TIME-OF-DAY, DATE-TIME and DURATION (§§8.26.1.1–8.26.5.1) are
// primitive. SEQUENCE and SEQUENCE OF (§§8.9.1, 8.10.1), SET and SET OF
// (§§8.11.1, 8.12.1), EMBEDDED PDV (§8.17.1), EXTERNAL (§8.18.1) and
// CHARACTER STRING (§8.24.1) are encoded as sequences, so constructed.
// validateDERUniversalValue applies the same forms.
func checkUniversalForm(t tag.Tag) error {
	if t.Class != tag.ClassUniversal {
		return nil
	}
	switch t.Number {
	case tag.TagBoolean, tag.TagInteger, tag.TagEnumerated, tag.TagReal,
		tag.TagNull, tag.TagObjectID, tag.TagRelativeOID, tag.TagOIDIRI,
		tag.TagRelativeOIDIRI, tag.TagTime, tag.TagDate, tag.TagTimeOfDay,
		tag.TagDateTime, tag.TagDuration:
		if t.Constructed {
			return fmt.Errorf("%w: X.690 (02/2021) requires primitive universal tag %d", ErrInvalidTag, t.Number)
		}
	case tag.TagSequence, tag.TagSet, tag.TagExternal, tag.TagEmbeddedPDV,
		tag.TagCharacterString:
		if !t.Constructed {
			return fmt.Errorf("%w: X.690 (02/2021) requires constructed universal tag %d", ErrInvalidTag, t.Number)
		}
	}
	return nil
}

// markBERForm records, on a decode that tracks BER forms, one element whose
// valid BER form the DER encoder would change. lengthOctets are the element's
// length octets; contents are its contents octets when the length is definite
// and within the input, else nil. The checks read only this element, so the
// whole-element scanner and every typed decoder share them.
func markBERForm(form *berFormState, t tag.Tag, lengthOctets []byte, indefinite bool, contents []byte) {
	if form == nil || form.preserve {
		return
	}
	// X.690 (02/2021) §§8.1.3, 10.1: BER permits indefinite and
	// nonminimal definite lengths; DER uses the shortest definite form.
	if indefinite || len(lengthOctets) > 1 &&
		(lengthOctets[1] == 0 || len(lengthOctets) == 2 && lengthOctets[1] < 0x80) {
		form.preserve = true
		return
	}
	if t.Class != tag.ClassUniversal {
		return
	}
	// X.690 (02/2021) §§8.2.1, 8.6.2, 8.7.3,
	// 10.2, 11.1–11.2: these BER values have a different DER form.
	switch t.Number {
	case tag.TagBitString, tag.TagOctetString, tag.TagObjectDesc,
		tag.TagUTF8String, tag.TagNumericString, tag.TagPrintableString,
		tag.TagT61String, tag.TagVideotexString, tag.TagIA5String,
		tag.TagGraphicString, tag.TagVisibleString, tag.TagGeneralString,
		tag.TagUniversalString, tag.TagBMPString:
		if t.Constructed {
			form.preserve = true
		} else if t.Number == tag.TagBitString && len(contents) > 1 && contents[0] <= 7 &&
			contents[len(contents)-1]&byte((1<<contents[0])-1) != 0 {
			// X.690 (02/2021) §§8.6.2.2, 11.2.1: retain BER padding
			// separately from the clean abstract value.
			form.preserve = true
		}
	case tag.TagBoolean:
		if !t.Constructed && len(contents) == 1 && contents[0] != 0 && contents[0] != 0xff {
			form.preserve = true
		}
	case tag.TagUTCTime, tag.TagGeneralizedTime:
		// The decoded value keeps any X.680 (02/2021) §46.3/§47.3 lexical
		// form, so only the constructed form (X.690 (02/2021) §8.23.6) needs
		// the original element.
		if t.Constructed {
			form.preserve = true
		}
	case tag.TagReal:
		if !t.Constructed && contents != nil {
			if len(contents) != 0 && contents[0]&0xc0 == 0 {
				// X.690 (02/2021) §11.3.2: the decimal DER form is
				// identifiable from its spelling, before bigint conversion.
				// The typed decoder validates the numeric value separately.
				if !canonicalDecimalRealContents(contents) {
					form.preserve = true
				}
				break
			}
			if decoded, decodeErr := decodeRealContents(contents); decodeErr == nil {
				if canonical, encodeErr := EncodeRealValue(decoded); encodeErr != nil || !bytes.Equal(contents, canonical) {
					form.preserve = true
				}
			}
		}
	}
}

// A structural scan knows the physical identifier before a generated decoder
// supplies its field name. Preserve that original position across both passes.
func scannedUTF8Location(data []byte, offset int, stack []berScanFrame, index int, config decodeConfig, options []DecodeOption) (Violation, error) {
	v := Violation{Path: qualifyConstraintPath(options, "")}
	if !config.tolerant {
		return v, nil
	}
	var relative []int
	if len(stack) > 1 {
		for _, ancestor := range stack[2:] {
			relative = append(relative, ancestor.index)
		}
		relative = append(relative, index)
	}
	v.ChildIndexes = relative
	if config.location != nil {
		// The scan is enabled only for a subslice of the located root.
		// The received identifier is therefore always directly locatable.
		absolute, ok := config.location.wireOffset(data[offset:])
		if !ok {
			return Violation{}, ErrInvalidLength
		}
		offset = absolute
		var err error
		v.ChildIndexes, err = config.location.origin.ancestry(offset)
		if err != nil {
			return Violation{}, err
		}
		v.Source = config.location.source
	}
	root := data
	if config.location != nil {
		root = config.location.origin.root
	}
	if len(root) != 0 {
		v.origin = weak.Make(&root[0])
	}
	v.Offset = new(offset)
	for _, child := range relative {
		v.Path = joinUTF8Path(v.Path, fmt.Sprintf("child[%d]", child))
	}
	return v, nil
}

func joinUTF8Path(prefix, leaf string) string {
	if prefix == "" {
		return leaf
	}
	if leaf == "" {
		return prefix
	}
	return prefix + "." + leaf
}
