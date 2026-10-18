// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/validation.go; SHA-256 2a8e572862eb483a91d512f68983347555281d3effdf4ef8e28ce3b1088a006a.
package ber

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// RuleRef identifies the published rule independently of diagnostic wording.
type RuleRef struct {
	Document string
	Edition  string
	Clause   string
	Erratum  string
}

// ViolationKind distinguishes source constraints from protocol text rules.
type ViolationKind uint8

const (
	ASN1Constraint ViolationKind = iota
	ProtocolRule
)

func identifyViolation(v Violation) Violation {
	if v.Rule.Document != "" {
		return v
	}
	v.Rule = RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51"}
	if strings.Contains(v.Constraint, "UTF8String") {
		v.Rule = RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.23.10"}
	}
	if strings.HasPrefix(v.Constraint, "Q.773") {
		v.Kind = ProtocolRule
		clause := "4.2.2.2"
		if strings.Contains(v.Constraint, "4.2.3") {
			clause = "4.2.3"
		}
		if strings.Contains(v.Constraint, "4.1.1") {
			clause = "4.1.1"
		}
		v.Rule = RuleRef{Document: "ITU-T Q.773", Edition: "06/1997", Clause: clause}
	}
	return v
}

type positionSearch struct {
	stack               []berScanFrame
	pos, elements, work int
	visits              *int
	target              int
	indexes             []int
}

type decodeOrigin struct {
	ancestryVisits int
	search         positionSearch
	located        map[int][]int
	limits         DecodeLimits
	profileType    string
	root           []byte
	marks          map[string]int
	pendingMarks   []decodedElementMark
}

type decodeLocation struct {
	origin  *decodeOrigin
	input   []byte
	offset  int
	source  string
	field   string
	context *generatedDecodeOption
}

type decodeLocationOption struct{ location *decodeLocation }

func (o decodeLocationOption) applyDecode(c *decodeConfig) error { c.location = o.location; return nil }

// LocateDecodedElement binds value checks to an identifier in the public input.
func LocateDecodedElement(data []byte, source string, options []DecodeOption) []DecodeOption {
	config, err := decodeOptions(options)
	if err != nil {
		return options
	}
	if len(options) == 1 {
		if parent, ok := options[0].(*generatedDecodeOption); ok {
			var located *locatedGeneratedDecodeOption
			if config.location == nil {
				root := new(rootLocatedGeneratedDecodeOption)
				root.origin.pendingMarks = root.marks[:0]
				located = &root.locatedGeneratedDecodeOption
				located.location.origin = &root.origin
			} else {
				located = new(locatedGeneratedDecodeOption)
			}
			initializeDecodeLocation(&located.location, data, source, config, options)
			located.context = *parent
			located.context.config.location = &located.location
			return []DecodeOption{&located.context}
		}
	}
	location := new(decodeLocation)
	initializeDecodeLocation(location, data, source, config, options)
	return append(options[:len(options):len(options)], decodeLocationOption{location})
}

// A generated context and its call-local location have the same lifetime.
// Keep their storage together instead of allocating each one independently.
type locatedGeneratedDecodeOption struct {
	context  generatedDecodeOption
	location decodeLocation
}

// Only the public root needs a new ancestry scanner. Its lifetime equals
// the root context's, so keep that state in the same allocation.
type rootLocatedGeneratedDecodeOption struct {
	locatedGeneratedDecodeOption
	origin decodeOrigin
	marks  [4]decodedElementMark
}

func initializeDecodeLocation(location *decodeLocation, data []byte, source string, config decodeConfig, options []DecodeOption) {
	location.input, location.source = data, source
	if config.location != nil {
		location.origin = config.location.origin
		location.offset = -1
		if len(options) == 1 {
			location.context, _ = options[0].(*generatedDecodeOption)
		}
		if location.context == nil {
			location.offset = config.location.receivedOffset()
			if offset, ok := config.location.wireOffset(data); ok {
				location.offset = offset
			} else if offset, ok := location.origin.mark(qualifyConstraintPath(options, "")); ok {
				location.offset = offset
			}
		}
	} else {
		if location.origin == nil {
			location.origin = new(decodeOrigin)
		}
		*location.origin = decodeOrigin{root: data, limits: config.limits, profileType: config.profileType, pendingMarks: location.origin.pendingMarks}
	}
}

// Reconstructed identifiers need their parent's received offset. Ordinary
// slices locate themselves in the root and never resolve this fallback.
func (location *decodeLocation) receivedOffset() int {
	if location.offset < 0 && location.context != nil {
		parent := location.context.config.location
		location.offset = parent.receivedOffset()
		if offset, ok := parent.wireOffset(location.input); ok {
			location.offset = offset
		} else if offset, ok := location.origin.contextMark(location.context); ok {
			location.offset = offset
		}
	}
	return location.offset
}

func (location *decodeLocation) wireOffset(data []byte) (int, bool) {
	if offset, ok := berSubsliceOffset(location.origin.root, data); ok {
		return offset, true
	}
	if offset, ok := berSubsliceOffset(location.input, data); ok {
		received := location.receivedOffset()
		header := func(input []byte) int {
			_, n, err := DecodeTag(input)
			if err != nil {
				return 0
			}
			_, _, m, err := DecodeLength(input[n:])
			if err != nil {
				return 0
			}
			return n + m
		}
		inputHeader := header(location.input)
		if offset >= inputHeader && received < len(location.origin.root) {
			relative := offset - inputHeader
			base := received + header(location.origin.root[received:])
			if base > len(location.origin.root) || relative > len(location.origin.root)-base {
				return 0, false
			}
			return base + relative, true
		}
		if received < 0 || received > len(location.origin.root) || offset > len(location.origin.root)-received {
			return 0, false
		}
		return received + offset, true
	}
	return 0, false
}

func hasDecodeLocation(options []DecodeOption) bool {
	for _, option := range options {
		switch option := option.(type) {
		case decodeLocationOption:
			return option.location != nil
		case *generatedDecodeOption:
			if option != nil && option.config.location != nil {
				return true
			}
		case diagnosticChildOption:
			if hasDecodeLocation(option.options) {
				return true
			}
		}
	}
	return false
}

func rememberDecodedElement(options []DecodeOption, name string, raw []byte) {
	if !hasDecodeLocation(options) {
		return
	}
	config, err := decodeOptions(options)
	if err != nil || config.location == nil {
		return
	}
	origin := config.location.origin
	if offset, ok := config.location.wireOffset(raw); ok {
		if len(options) == 1 {
			if context, ok := options[0].(*generatedDecodeOption); ok {
				if origin.pendingMarks == nil {
					origin.pendingMarks = make([]decodedElementMark, 0, 8)
				}
				origin.pendingMarks = append(origin.pendingMarks, decodedElementMark{context: context, name: name, offset: offset})
				config.location.field = name
				return
			}
		}
		_, _ = origin.mark("")
		origin.remember(qualifyConstraintPath(options, name), offset)
		config.location.field = name
	}
}

// The schema path is consumed only by a failed check or a location lookup
// for a reconstructed IMPLICIT value. Successful field visits retain the
// immutable context and identifier offset, without joining path strings.
type decodedElementMark struct {
	context *generatedDecodeOption
	name    string
	offset  int
}

func (origin *decodeOrigin) remember(path string, offset int) {
	if origin.marks == nil {
		origin.marks = make(map[string]int)
	}
	origin.marks[path] = offset
}

func (origin *decodeOrigin) mark(path string) (int, bool) {
	for _, mark := range origin.pendingMarks {
		prefix := generatedConstraintPath(mark.context)
		name := mark.name
		if prefix != "" {
			if name != "" {
				name = prefix + "." + name
			} else {
				name = prefix
			}
		}
		origin.remember(name, mark.offset)
	}
	origin.pendingMarks = origin.pendingMarks[:0]
	offset, ok := origin.marks[path]
	return offset, ok
}

// An IMPLICIT child is normally decoded immediately after its field marker.
// Match that immutable path structurally before spelling diagnostic strings.
func (origin *decodeOrigin) contextMark(context *generatedDecodeOption) (int, bool) {
	if count := len(origin.pendingMarks); count != 0 && context != nil {
		last := origin.pendingMarks[count-1]
		if last.name == "" && sameGeneratedDecodePath(context, last.context) || !context.isElement && context.pathOptions == nil && context.component == last.name && sameGeneratedDecodePath(context.parent, last.context) {
			return last.offset, true
		}
	}
	return origin.mark(generatedConstraintPath(context))
}

func sameGeneratedDecodePath(first, second *generatedDecodeOption) bool {
	for first != second {
		if first == nil || second == nil || first.pathOptions != nil || second.pathOptions != nil || first.component != second.component || first.isElement != second.isElement || first.element != second.element {
			return false
		}
		first, second = first.parent, second.parent
	}
	return true
}

func locateViolation(config decodeConfig, v Violation, leaf string) (Violation, error) {
	if config.location == nil {
		return v, nil
	}
	location := config.location
	offset := location.receivedOffset()
	for path := v.Path; path != ""; {
		if found, ok := location.origin.mark(path); ok {
			offset = found
			break
		}
		index := strings.LastIndex(path, ".")
		if index < 0 {
			break
		}
		path = path[:index]
	}
	v.Offset = new(offset)
	var err error
	v.ChildIndexes, err = location.origin.ancestry(offset)
	v.Source = sourceField(location.source, leaf)
	return v, err
}

// Locate requested identifiers in a resumable path-only scan. Memory tracks
// the ancestor stack and requested records, never every preceding sibling.
// Header and primitive-content visits share one MaxWork budget across lookups.
func (origin *decodeOrigin) ancestry(target int) ([]int, error) {
	if target <= 0 {
		return nil, nil
	}
	if indexes, ok := origin.located[target]; ok {
		return append([]int(nil), indexes...), nil
	}
	search := &origin.search
	search.target, search.indexes, search.visits = target, nil, &origin.ancestryVisits
	collect := decodeOptionFunc(func(c *decodeConfig) error {
		c.limits = origin.limits
		c.profile = true
		c.profileType = origin.profileType
		c.positionSearch = search
		c.collectPositionsOnly = true
		return nil
	})
	if err := ValidateBERElement(origin.root, collect); err != nil {
		return nil, err
	}
	if origin.located == nil {
		origin.located = make(map[int][]int)
	}
	origin.located[target] = append([]int(nil), search.indexes...)
	return search.indexes, nil
}

// WithoutReplayCapture omits received-form provenance after ordinary validation.
// Required raw payloads remain available. Later encoding rebuilds owned values.
func WithoutReplayCapture() DecodeOption {
	return decodeOptionFunc(func(c *decodeConfig) error { c.noReplayCapture = true; return nil })
}

// ReplayCaptureEnabled reports whether a validated option set retains form.
func ReplayCaptureEnabled(options []DecodeOption) bool {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			return !context.config.noReplayCapture
		}
	}
	c, err := decodeOptions(options)
	return err == nil && !c.noReplayCapture
}

// LocateDialogueContent translates a recognized EXTERNAL encoding back to
// its received octets before the typed inner decoder examines copied bytes.
// Q.773 (06/1997) §4.2.3; X.690 (02/2021) §8.18.6.
func LocateDialogueContent(data, inner []byte, options []DecodeOption) []DecodeOption {
	config, err := decodeOptions(options)
	if err != nil || config.location == nil {
		return options
	}
	_, _, external, err := DecodeTLV(data, options...)
	if err != nil {
		return options
	}
	_, _, body, err := DecodeTLV(external, options...)
	if err != nil {
		return options
	}
	for pos := 0; pos < len(body); {
		identifier, n, contents, err := DecodeTLV(body[pos:], options...)
		if err != nil || n <= 0 {
			return options
		}
		if identifier.Class == 2 && identifier.Number >= 0 && identifier.Number <= 2 {
			if identifier.Constructed && identifier.Number != 0 {
				return options
			}
			if identifier.Number == 2 {
				if len(contents) == 0 {
					return options
				}
				contents = contents[1:]
			}
			if offset, ok := config.location.wireOffset(contents); ok {
				// Keep resolved policy and linked paths for the copied typed
				// payload. Its received location belongs to this call only.
				if len(options) == 1 {
					if parent, ok := options[0].(*generatedDecodeOption); ok {
						located := new(locatedGeneratedDecodeOption)
						located.context = *parent
						located.location = decodeLocation{origin: config.location.origin, input: inner, offset: offset, source: "DialoguePortion"}
						located.context.config.location = &located.location
						return []DecodeOption{&located.context}
					}
				}
				location := &decodeLocation{origin: config.location.origin, input: inner, offset: offset, source: "DialoguePortion"}
				return append(options[:len(options):len(options)], decodeLocationOption{location})
			}
			return options
		}
		pos += n
	}
	return options
}

// LocateDecodeError locates a typed failure after bounded BER preflight.
// Existing element locations and causes are retained through nested codecs.
func LocateDecodeError(err error, options []DecodeOption) error {
	if err == nil {
		return nil
	}
	var element *ElementError
	if errors.As(err, &element) {
		return err
	}
	config, optionErr := decodeOptions(options)
	if optionErr != nil || config.location == nil {
		return err
	}
	offset := config.location.receivedOffset()
	indexes, _ := config.location.origin.ancestry(offset)
	var validation *ValidationError
	if errors.As(err, &validation) && validation.Offset != nil {
		offset = *validation.Offset
		indexes = validation.ChildIndexes
	}
	return &ElementError{offset: offset, childIndexes: append([]int(nil), indexes...), cause: err}
}

// ObserveInteger bounds diagnostic formatting work for arbitrary-width IDs.
// Small values retain decimal observations. Large values use a sign, bit count
// and magnitude digest, avoiding a superlinear decimal conversion. This is an
// operational reporting policy, separate from X.690 (02/2021) §8.3's encoding.
func ObserveInteger(value any) string {
	if integer, ok := value.(*big.Int); ok && integer != nil && integer.BitLen() > 1024 {
		digest := sha256.Sum256(integer.Bytes())
		return fmt.Sprintf("INTEGER sign=%d bits=%d sha256=%x", integer.Sign(), integer.BitLen(), digest)
	}
	return fmt.Sprint(value)
}

func sourceField(source, field string) string {
	if source == "" {
		return ""
	}
	assignment := source[strings.LastIndex(source, ".")+1:]
	if field == "" || strings.EqualFold(strings.ReplaceAll(assignment, "-", ""), strings.ReplaceAll(field, "-", "")) {
		return source
	}
	return source + "." + field
}

type encodeSourceOption string

func (source encodeSourceOption) applyEncode(c *encodeConfig) error {
	c.source = string(source)
	return nil
}

// EncodeSource attaches the pinned source assignment to a generated check.
// It changes diagnostic metadata only; tolerance and replay policy are retained.
func EncodeSource(options []EncodeOption, source string) []EncodeOption {
	return append(options[:len(options):len(options)], encodeSourceOption(source))
}
