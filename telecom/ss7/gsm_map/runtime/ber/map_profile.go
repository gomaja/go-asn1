// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/map_profile.go; SHA-256 b279d6e769fcc2f76d2e1daeef34d609a6c1ed994c06ad8e03a5f59813a5ae78.
package ber

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"weak"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// TrackMAPForm selects TS 29.002 V19.1.0 §17.1.1 for generated MAP
// codecs. A standalone ValidateBERElement call with this option refuses:
// only a typed decoder can identify MAP-owned content and foreign open
// values (X.690 (02/2021) §8.15). Generic BER scans need no profile option.
// The returned options support sequential and concurrent generated root decodes.
func TrackMAPForm(options []DecodeOption) []DecodeOption {
	return TrackMAPSyntax(options, true)
}

// TrackMAPSyntax selects the root syntax's profile once. TS 29.002 V19.1.0
// §17.1.1 covers its defined abstract syntaxes; X.880 and TS 24.080 roots
// retain generic X.690 BER, including nested imported MAP definitions.
func TrackMAPSyntax(options []DecodeOption, enabled bool) []DecodeOption {
	options = TrackBERForm(options)
	if len(options) == 1 {
		switch option := options[0].(type) {
		case berFormOption:
			setMAPSyntax(option.state, enabled)
			return options
		case *generatedDecodeOption:
			if option != nil {
				setMAPSyntax(option.config.form, enabled)
			}
			return options
		}
	}
	for _, option := range options {
		switch value := option.(type) {
		case berFormOption:
			setMAPSyntax(value.state, enabled)
			return options
		case *generatedDecodeOption:
			if value != nil {
				setMAPSyntax(value.config.form, enabled)
			}
			return options
		case diagnosticChildOption:
			TrackMAPSyntax(value.options, enabled)
			return options
		}
	}
	return options
}

// The three syntax states share the original one-byte profile slot.
// Keeping the decode marker's size unchanged preserves valid-input budgets.
const (
	mapSyntaxGeneric   uint8 = 1
	mapSyntaxProfile   uint8 = 2
	mapSyntaxGenerated uint8 = 3
)

func (form *berFormState) mapProfile() bool { return form.mapSyntax >= mapSyntaxProfile }
func setMAPSyntax(form *berFormState, enabled bool) {
	if form != nil && form.mapSyntax == 0 {
		form.mapSyntax = mapSyntaxGeneric
		if enabled {
			form.mapSyntax = mapSyntaxProfile
		}
	}
}

type mapProfileState struct {
	root       []byte
	byOffset   map[int]*mapProfileElement
	offsets    []int
	candidates []int
	failure    error
}

type mapProfileElement struct {
	rules        uint8
	owned        bool
	listed       bool
	path, source string
	segments     *mapProfileSegments
}

// Fragment locations are materialized only for reports that can be emitted.
// A known string shares its semantic location across all fragment candidates.
type mapProfileSegments struct {
	path, source string
	depth        int
}

const (
	mapShortLength uint8 = 1 << iota
	mapMinimumLength
	mapPrimitiveOctets
	mapPrimitiveBits
)

var mapRuleNames = [...]string{"short-length", "minimum-length-octets", "primitive-octet-string", "primitive-bit-string"}
var mapRuleBits = [...]uint8{mapShortLength, mapMinimumLength, mapPrimitiveOctets, mapPrimitiveBits}

func mapProfileRules(t tag.Tag, length []byte, indefinite bool) (rules uint8) {
	// TS 29.002 V19.1.0 §17.1.1. Empty constructors and constructed
	// indefinite lengths remain legal (X.690 (02/2021) §8.1.3.6).
	if !indefinite && len(length) > 1 {
		if len(length) == 2 && length[1] < 128 {
			rules |= mapShortLength
		} else if length[1] == 0 {
			rules |= mapMinimumLength
		}
	}
	if t.Constructed && t.Class == tag.ClassUniversal {
		if t.Number == tag.TagOctetString {
			rules |= mapPrimitiveOctets
		}
		if t.Number == tag.TagBitString {
			rules |= mapPrimitiveBits
		}
	}
	return rules
}

func collectMAPForm(form *berFormState, data []byte, offset int, t tag.Tag, length []byte, indefinite bool) {
	if form == nil || !form.mapProfile() {
		return
	}
	rules := mapProfileRules(t, length, indefinite)
	if rules == 0 {
		return
	}
	if form.mapPending == nil {
		form.mapPending = &mapProfileState{root: data, byOffset: make(map[int]*mapProfileElement)}
	}
	pending := form.mapPending
	base, ok := berSubsliceOffset(pending.root, data)
	if !ok {
		return
	} // A reconstructed IMPLICIT identifier has no received header.
	if offset < 0 || offset >= len(data) || base > len(pending.root) || offset > len(pending.root)-base {
		return
	}
	absolute := base + offset
	if pending.byOffset[absolute] == nil {
		pending.candidates = append(pending.candidates, absolute)
	}
	pending.add(absolute, rules)
}

func (pending *mapProfileState) add(offset int, rules uint8) *mapProfileElement {
	element := pending.byOffset[offset]
	if element == nil {
		element = new(mapProfileElement)
		pending.byOffset[offset] = element
	}
	element.rules |= rules
	return element
}

// A schema visit claims only its own identifier. Unknown additions are never
// visited as MAP types. An unresolved open value is subsequently excluded in
// its entirety, header included: TS 29.002 §17.1.1; X.690 (02/2021) §8.15.
func claimMAPElement(config decodeConfig, options []DecodeOption, name string, raw []byte) {
	if config.form == nil || config.form.mapPending == nil || config.location == nil {
		return
	}
	offset, ok := config.location.wireOffset(raw)
	if !ok {
		return
	}
	if _, received := berSubsliceOffset(config.location.origin.root, raw); !received {
		if relative, within := berSubsliceOffset(config.location.input, raw); within && relative == 0 {
			return
		}
	}
	element := config.form.mapPending.byOffset[offset]
	if element == nil {
		return
	}
	if !element.listed {
		config.form.mapPending.offsets = append(config.form.mapPending.offsets, offset)
		element.listed = true
	}
	element.owned = true
	element.segments = nil
	element.path = qualifyConstraintPath(options, name)
	element.source = sourceField(config.location.source, name)
}

// X.690 (02/2021) §§8.6.4, 8.7.3 keep segments within the known string
// type. Only candidate headers need location work; opaque values never call
// this typed hook. Disjoint string intervals visit each candidate once.
func claimMAPStringSegments(data []byte, whole bool, options []DecodeOption) {
	config, err := decodeOptions(options)
	if err != nil || config.form == nil || config.form.mapPending == nil || config.location == nil {
		return
	}
	if whole {
		_, _, contents, err := DecodeTLV(data, options...)
		if err != nil {
			return
		}
		data = contents
	}
	start, ok := config.location.wireOffset(data)
	if !ok {
		return
	}
	leaf := config.location.fieldName()
	path := qualifyConstraintPath(options, "")
	if leaf != "" && !config.location.fieldAlreadyApplied(options) {
		path = joinUTF8Path(path, leaf)
	}
	base, err := locateViolation(config, Violation{Path: path}, leaf)
	if err != nil {
		return
	}
	pending := config.form.mapPending
	segments := &mapProfileSegments{path: path, source: base.Source, depth: len(base.ChildIndexes)}
	for i := sort.SearchInts(pending.candidates, start); i < len(pending.candidates); i++ {
		offset := pending.candidates[i]
		if offset < start {
			continue
		}
		if offset-start >= len(data) {
			break
		}
		element := pending.byOffset[offset]
		if !element.listed {
			pending.offsets = append(pending.offsets, offset)
			element.listed = true
		}
		element.owned, element.segments = true, segments
	}
}

func claimMAPPrimitive(data []byte, options []DecodeOption) {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && (context.config.form == nil || context.config.form.mapPending == nil) {
			return
		}
	}
	config, err := decodeOptions(options)
	if err != nil || config.form == nil || config.form.mapPending == nil || config.location == nil {
		return
	}
	leaf := config.location.fieldName()
	if config.location.fieldAlreadyApplied(options) {
		leaf = ""
	}
	claimMAPElement(config, options, leaf, data)
}

func excludeMAPOpaque(config decodeConfig, raw []byte, length int) {
	if config.form == nil || config.form.mapPending == nil || config.location == nil || length < 0 || length > len(raw) {
		return
	}
	start, ok := config.location.wireOffset(raw)
	if !ok {
		return
	}
	// Only the field's outer identifier can have been visited as MAP syntax;
	// no typed decoder visits descendants of an unresolved open value.
	if element := config.form.mapPending.byOffset[start]; element != nil {
		element.owned = false
	}
}

func beginMAPDecode(form *berFormState, location *decodeLocation, options []DecodeOption, data []byte) {
	if form == nil || !form.mapProfile() {
		return
	}
	if form.mapDepth == math.MaxUint32 {
		if form.mapPending == nil {
			form.mapPending = &mapProfileState{byOffset: make(map[int]*mapProfileElement)}
		}
		form.mapPending.failure = fmt.Errorf("%w: MAP generated-entry depth exceeded", ErrResourceLimit)
		return
	}
	form.mapDepth++
	if form.mapPending != nil {
		claimMAPElement(decodeConfig{form: form, location: location}, options, "", data)
	}
}

func finishMAPDecode(prior error, config decodeConfig) error {
	form := config.form
	if form == nil || !form.mapProfile() || form.mapDepth == 0 {
		return nil
	}
	if form.mapPending != nil && form.mapPending.failure != nil {
		return form.mapPending.failure
	}
	form.mapDepth--
	if form.mapDepth != 0 || prior != nil || form.mapPending == nil {
		return nil
	}
	pending := form.mapPending
	for _, offset := range pending.offsets {
		element := pending.byOffset[offset]
		if !element.owned {
			continue
		}
		for bit, name := range mapRuleNames {
			if element.rules&mapRuleBits[bit] == 0 {
				continue
			}
			v := Violation{Kind: ProtocolRule, Rule: RuleRef{Document: "3GPP TS 29.002", Edition: "V19.1.0", Clause: "17.1.1"}, Constraint: "TS 29.002 §17.1.1: " + name, Path: element.path, Source: element.source, Offset: new(offset), ObservedValue: "received BER form", scope: config.reportScope}
			if config.location != nil {
				var err error
				v.ChildIndexes, err = config.location.origin.ancestry(offset)
				if err != nil {
					return err
				}
			}
			if segments := element.segments; segments != nil {
				var path strings.Builder
				path.WriteString(segments.path)
				for _, index := range v.ChildIndexes[min(len(v.ChildIndexes), segments.depth):] {
					if path.Len() != 0 {
						path.WriteByte('.')
					}
					path.WriteString("child[")
					path.WriteString(strconv.Itoa(index))
					path.WriteByte(']')
				}
				v.Path, v.Source = path.String(), segments.source
			}
			if len(pending.root) > 0 {
				v.origin = weak.Make(&pending.root[0])
				v.source = v.origin
			}
			if !config.tolerant {
				return &ValidationError{boundedViolation(v)}
			}
			if err := config.violations.append(v, config.diagnostics); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkMAPStringForm(constructed bool, kind int, options []DecodeOption) error {
	if !constructed {
		return nil
	}
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	if config.form == nil || !config.form.mapProfile() || config.location == nil {
		return nil
	}
	location := config.location
	leaf := location.fieldName()
	path := qualifyConstraintPath(options, "")
	if leaf != "" && !location.fieldAlreadyApplied(options) {
		path = joinUTF8Path(path, leaf)
	}
	v, err := locateViolation(config, Violation{Path: path}, leaf)
	if err != nil {
		return err
	}
	if config.form.mapPending == nil {
		config.form.mapPending = &mapProfileState{root: location.origin.root, byOffset: make(map[int]*mapProfileElement)}
	}
	rule := mapPrimitiveOctets
	if kind == tag.TagBitString {
		rule = mapPrimitiveBits
	}
	element := config.form.mapPending.add(*v.Offset, rule)
	if !element.listed {
		config.form.mapPending.offsets = append(config.form.mapPending.offsets, *v.Offset)
		element.listed = true
	}
	element.owned, element.path, element.source = true, path, v.Source
	return nil
}

// MAPEncodeBoundary identifies the single public final-byte check. The
// generated marker and replay modes already delimit nested encode work.
func MAPEncodeBoundary(options []EncodeOption) bool {
	for _, option := range options {
		switch option.(type) {
		case generatedEncodeMarker, replayModeOption:
			return false
		}
	}
	return true
}

// CheckMAPEncoded checks the final public bytes after replay selection. Fresh
// typed output is primitive and minimally length-encoded by construction;
// unchanged received bytes from a clean MAP decode have the same proof.
// A retained child with findings requests a deferred root pass, so a rebuilt
// parent is checked only when such a child was actually replayed.
// TS 29.002 V19.1.0 §17.1.1; X.690 (02/2021) §8.15 leaves open values opaque.
func CheckMAPEncoded(data []byte, node *ReplayNode, options []EncodeOption, decode func([]byte, ...DecodeOption) error) error {
	if node != nil && node.state != nil && node.state.mapProfileChecked && !node.state.mapViolations {
		return nil
	}
	if mapEncodeSuppressed(options) {
		return nil
	}
	if !mapFormNeedsTypedCheck(data) {
		return nil
	}
	return checkMAPEncoded(data, options, decode)
}

var errMAPEncodeCheck = errors.New("MAP final encoding check required")

type mapEncodePassOption struct{}

func (mapEncodePassOption) applyEncode(*encodeConfig) error { return nil }

type mapGenericEncodeOption struct{}

func (mapGenericEncodeOption) applyEncode(*encodeConfig) error { return nil }
func mapEncodeSuppressed(options []EncodeOption) bool {
	for _, o := range options {
		switch mode := o.(type) {
		case replayModeOption:
			if mode.baseline || mode.comparison || mode.collector != nil || mode.fast != nil {
				return true
			}
		case mapEncodePassOption, mapGenericEncodeOption:
			return true
		}
	}
	return false
}

// GenericMAPEncodeOptions keeps an unrelated root syntax outside §17.1.1.
// Nested entries inherit that choice, just as TrackMAPSyntax does on decode.
func GenericMAPEncodeOptions(options []EncodeOption) []EncodeOption {
	if !MAPEncodeBoundary(options) {
		return options
	}
	return append(options[:len(options):len(options)], mapGenericEncodeOption{})
}

// DeferMAPEncodeCheck requests a final root pass only for retained profile
// findings. Clean replay nodes require no scan or mutable per-call stage.
func DeferMAPEncodeCheck(node *ReplayNode, options []EncodeOption, external ...[]byte) error {
	if len(external) > 0 {
		if mapEncodeSuppressed(options) || !mapFormNeedsTypedCheck(external[0]) {
			return nil
		}
		return errMAPEncodeCheck
	}
	if node == nil || node.state == nil || node.state.mapProfileChecked && !node.state.mapViolations || mapEncodeSuppressed(options) {
		return nil
	}
	// An edited root repairs its retained MAP spans before the single public
	// check. A nested entry must not abort that repair with a deferred refusal.
	// This path is reached only for retained findings; valid-value encodes do
	// not search their option chain. TS 29.002 V19.1.0 §17.1.1;
	// X.690 (02/2021) §8.1.3.
	for _, option := range options {
		if mode, ok := option.(replayModeOption); ok && mode.state == node.state && mode.rebuildChildren {
			return nil
		}
	}
	return errMAPEncodeCheck
}

// RetryMAPEncode defers a retained child's profile check to the final public
// bytes. Only the uncommon retained-violation path needs another encode pass;
// fresh typed output and clean decoded nodes already prove §17.1.1.
func RetryMAPEncode(err error, options []EncodeOption) ([]EncodeOption, bool) {
	if !errors.Is(err, errMAPEncodeCheck) {
		return options, false
	}
	return append(options[:len(options):len(options)], mapEncodePassOption{}), true
}

// CheckMAPEncodedElement checks entries whose received form is held by a
// named EXTERNAL rather than a ReplayNode. X.690 (02/2021) §8.18.
func CheckMAPEncodedElement(data []byte, options []EncodeOption, decode func([]byte, ...DecodeOption) error) error {
	if mapEncodeSuppressed(options) {
		return nil
	}
	if !mapFormNeedsTypedCheck(data) {
		return nil
	}
	return checkMAPEncoded(data, options, decode)
}

// A final stream without nonminimal lengths or possible constructed strings
// already proves §17.1.1. This allocation-free pass only selects a typed walk;
// it never assigns an unknown IMPLICIT type or publishes a finding.
func mapFormNeedsTypedCheck(data []byte) bool {
	for len(data) > 0 {
		if len(data) < 2 {
			return true
		}
		identifier := data[0]
		header, length, indefinite := 2, int(data[1]), false
		class, number, constructed := identifier>>6, int(identifier&31), identifier&32 != 0
		if number == 31 || data[1] >= 128 {
			t, n, err := DecodeTag(data)
			if err != nil || n < 0 || n > len(data) {
				return true
			}
			decoded, indef, m, err := DecodeLength(data[n:])
			if err != nil || m < 0 || m > len(data)-n {
				return true
			}
			if mapProfileRules(t, data[n:n+m], indef) != 0 {
				return true
			}
			header, length, indefinite = n+m, decoded, indef
			class, number, constructed = byte(t.Class), t.Number, t.Constructed
		} else if identifier == 0x23 || identifier == 0x24 {
			return true
		}
		data = data[header:]
		if !indefinite && length > len(data) {
			return true
		}
		if constructed {
			if class != byte(tag.ClassUniversal) || number != tag.TagSequence && number != tag.TagSet && number != tag.TagExternal {
				if len(data) == 0 || !indefinite && length == 0 {
					return true
				}
				child := data[0]
				if child == 0 || child&0xc0 == 0 && (child&31 == tag.TagBitString || child&31 == tag.TagOctetString) {
					return true
				}
			}
		} else {
			if indefinite {
				return true
			}
			data = data[length:]
		}
	}
	return false
}

func checkMAPEncoded(data []byte, options []EncodeOption, decode func([]byte, ...DecodeOption) error) error {
	if decode == nil {
		return fmt.Errorf("%w: missing MAP profile decoder", ErrInvalidCodec)
	}
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if !config.tolerant {
		err := decode(data, WithoutReplayCapture(), encodingStructureOption(data))
		var refusal *ValidationError
		if errors.As(err, &refusal) {
			record := refusal.Violation
			record.Offset, record.OctetOffset, record.ChildIndexes = nil, nil, nil
			return &ValidationError{record}
		}
		return err
	}
	var log ViolationLog
	if err := decode(data, WithTolerance(&log), WithoutReplayCapture(), encodingStructureOption(data)); err != nil {
		return err
	}
	for _, v := range log.Snapshot() {
		if v.Kind != ProtocolRule || v.Rule.Document != "3GPP TS 29.002" || v.Rule.Clause != "17.1.1" {
			continue
		}
		v.scope = config.reportScope
		// Final bytes locate abstract positions for this encode, not received
		// wire coordinates. Paths retain distinct fields and collection entries.
		v.Offset, v.OctetOffset, v.ChildIndexes = nil, nil, nil
		v.encodeRecord = true
		if err := config.violations.append(v, DefaultDiagnosticLimits()); err != nil {
			return err
		}
	}
	return nil
}
