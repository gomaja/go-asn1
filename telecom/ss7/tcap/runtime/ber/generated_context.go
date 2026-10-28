// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_context.go; SHA-256 94718a09a5c67850c79231afa3adf24bc2d783f895099645f1d4bba7cb23aeef.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"reflect"
	"strings"
	"unsafe"
)

// validatedBERSource holds the owned input. Proof mode also records element
// boundaries from the complete X.690 structural and universal-content scan.
type validatedBERSource struct {
	light         bool // ordinary child validation; no validated-span proof
	input         []byte
	owned         []byte
	validated     []byte
	reconstructed bool
	spans         map[int]int
	shortSpans    []uint16
	replay        *ReplayState
}

// generatedDecodeOption is intentionally unexported. A zero or caller-made
// DecodeOption cannot claim that an arbitrary slice passed preflight.
type generatedDecodeOption struct {
	source      *validatedBERSource
	config      decodeConfig
	parent      *generatedDecodeOption
	component   string
	element     int
	isElement   bool
	pending     *validatedBERSource
	pathOptions []DecodeOption
	path        string
	pathSet     bool
	validated   bool // immutable proof of source ownership, numeric policy and local path checks
	location    decodeLocation
}

// diagnosticChildOption retains the parent path without building a child
// option slice. A failed preflight materializes the path for its probe.
type diagnosticChildOption struct {
	options               []DecodeOption
	component             string
	element               int
	isElement             bool
	collectionSizeChecked bool
}

func (option diagnosticChildOption) applyDecode(config *decodeConfig) error {
	resolved, err := decodeOptions(option.options)
	if err != nil {
		return err
	}
	if option.isElement {
		if option.element < 0 {
			return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
		}
	} else if option.component == "" || strings.Contains(option.component, ".") {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	resolved.hasPath = true
	resolved.collectionSizeChecked = option.collectionSizeChecked
	*config = resolved
	return nil
}

func expandGeneratedDecodeOptions(options []DecodeOption) []DecodeOption {
	for index, option := range options {
		if diagnostic, ok := option.(diagnosticChildOption); ok {
			// Normal generated calls have no diagnostic option. Keep their
			// preflight path as the original slice without probing each option.
			if !generatedPreflightProbeActive(diagnostic.options) {
				continue
			}
			parent := expandGeneratedDecodeOptions(diagnostic.options)
			var expanded []DecodeOption
			expanded = append(expanded, options[:index]...)
			expanded = append(expanded, parent...)
			if diagnostic.isElement {
				expanded = append(expanded, constraintPathOption(fmt.Sprintf("element[%d]", diagnostic.element)))
			} else {
				expanded = append(expanded, constraintPathOption(diagnostic.component))
			}
			if diagnostic.collectionSizeChecked {
				expanded = append(expanded, parentCollectionSizeOption{})
			}
			expanded = append(expanded, options[index+1:]...)
			return expanded
		}
	}
	return options
}

func generatedPreflightProbeActive(options []DecodeOption) bool {
	for _, option := range options {
		if probe, ok := option.(preflightProbeOption); ok && probe.state != nil && probe.state.active {
			return true
		}
		if child, ok := option.(diagnosticChildOption); ok && generatedPreflightProbeActive(child.options) {
			return true
		}
	}
	return false
}

// ChildDecodeIndexContext defers collection-index formatting until a
// violation or diagnostic needs the path.
func ChildDecodeIndexContext(options []DecodeOption, index int) DecodeOption {
	if len(options) != 0 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			config, err := decodeOptions(options)
			if err == nil {
				child := &generatedDecodeOption{source: context.source, config: config, parent: context, element: index, isElement: true, pending: context.pending, validated: index >= 0}
				child.config.collectionSizeChecked = false
				if len(options) > 1 {
					child.pathOptions = options
				}
				child.config.hasPath = true
				return child
			}
		}
	}
	return diagnosticChildOption{options: options, element: index, isElement: true}
}

// ChildDecodeIndexOptions keeps the light path's ordinary option slice while
// a proof context defers collection-index formatting until an error needs it.
func ChildDecodeIndexOptions(options []DecodeOption, index int) []DecodeOption {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			return []DecodeOption{ChildDecodeIndexContext(options, index)}
		}
	}
	return ChildDecodeOptions(options, fmt.Sprintf("element[%d]", index))
}

func isGeneratedDecodeContext(option DecodeOption) bool {
	_, ok := option.(*generatedDecodeOption)
	return ok
}

func (option *generatedDecodeOption) validate() error {
	if option != nil && option.validated {
		return nil
	}
	if option == nil || option.source == nil || option.source.owned == nil {
		return fmt.Errorf("%w: invalid generated BER decode context", ErrInvalidValue)
	}
	if option.parent != nil && (!option.isElement && (option.component == "" || strings.Contains(option.component, ".")) || option.isElement && option.element < 0) {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	return nil
}

func (option *generatedDecodeOption) applyDecode(config *decodeConfig) error {
	if err := option.validate(); err != nil {
		return err
	}
	*config = option.config
	return nil
}

// OwnGeneratedBERInput gives the generated decoder one working input copy.
// Light mode keeps it as the received-octet copy; proof mode adds a separate
// private validated copy. Callers must not modify input while decoding.
func OwnGeneratedBERInput(data []byte, options []DecodeOption) ([]byte, error) {
	// A child of a shallow decode already reads the root's working copy.
	// Its form marker is direct, while diagnostic probes wrap their options.
	for _, option := range options {
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.lightInput != nil {
			return data, nil
		}
	}
	// Diagnostic children carry their probe inside one path option. Ordinary
	// calls have no such option and can skip the recursive expansion.
	for _, option := range options {
		if _, diagnostic := option.(diagnosticChildOption); !diagnostic {
			continue
		}
		expanded := expandGeneratedDecodeOptions(options)
		if len(expanded) != 0 {
			if probe, ok := expanded[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
				return data, nil
			}
		}
		break
	}
	if len(options) != 0 {
		if probe, ok := options[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
			return data, nil
		}
	}
	if len(options) != 0 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			if context.source == nil || context.source.owned == nil {
				return nil, fmt.Errorf("%w: invalid generated BER decode context", ErrInvalidValue)
			}
			if context.config.limits.MaxWork > 0 && len(data) > context.config.limits.MaxWork {
				return data, nil
			}
			// Light children already read the root's working input or a
			// private reconstructed buffer. Preserve that received-location
			// relationship just as the ordinary option path does.
			if context.source.light {
				return data, nil
			}
			if _, within := berSubsliceOffset(context.source.owned, data); within {
				if !context.source.matchesValidated(data) {
					if err := ValidateBERElement(data, options...); err != nil {
						return nil, err
					}
				}
				return data, nil
			}
			return append([]byte(nil), data...), nil
		}
	}
	// Reject before retaining input or constructing a replay span map. Any
	// tolerant preliminary findings have a private diagnostic scope. go-asn1
	// #150 remains separate: this guard belongs to TCAP's owned runtime.
	config, optionErr := decodeOptions(options)
	if optionErr != nil {
		return nil, optionErr
	}
	preliminary := config
	if preliminary.form != nil && preliminary.form.lightInput == nil && preliminary.form.owned == nil && preliminary.form.lightOwned == nil {
		preliminary.form = nil
		preliminary.generatedPreflight = true
		if preliminary.tolerant {
			preliminary.violations = new(ViolationLog)
			preliminary.reportScope = new(reportScope)
		}
		if err := validateBERElement(data, nil, preliminary); err != nil {
			return data, nil
		}
	}
	if len(options) == 1 {
		if form, ok := options[0].(berFormOption); ok && form.state != nil && config.generatedMode != generatedModeProof {
			form.state.generated = true
			if config.generatedMode != generatedModeLight && rootHasIndefiniteLength(data) && len(data) <= config.limits.MaxWork {
				form.state.owned = bytes.Clone(data)
				return form.state.owned, nil
			}
			if len(data) <= config.limits.MaxWork {
				form.state.lightOwned = bytes.Clone(data)
				return form.state.lightOwned, nil
			}
			return data, nil
		}
	}
	if config.form == nil {
		return nil, fmt.Errorf("%w: generated BER form tracker is unavailable", ErrInvalidValue)
	}
	config.form.generated = true
	if config.generatedMode == generatedModeProof || config.generatedMode != generatedModeLight && config.form.lightInput == nil && rootHasIndefiniteLength(data) {
		if len(data) > config.limits.MaxWork {
			return data, nil
		}
		config.form.owned = bytes.Clone(data)
		return config.form.owned, nil
	}
	if config.form.lightInput == nil && len(data) <= config.limits.MaxWork {
		config.form.lightOwned = bytes.Clone(data)
		return config.form.lightOwned, nil
	}
	return data, nil
}

// PrepareGeneratedBERInput binds generated decoding to a complete element.
// Proof mode exposes one working copy to generated decoders and keeps a
// private copy of its validated bytes. A changed span is scanned again before
// its recorded boundary can be used. Light mode keeps ordinary nested checks.
// Callers must not change input while a decode is in progress.
// A new implicit identifier is validated under its universal tag.
func PrepareGeneratedBERInput(data []byte, options []DecodeOption) ([]byte, []DecodeOption, error) {
	for _, option := range options {
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.lightInput != nil {
			if err := ValidateBERElement(data, options...); err != nil {
				return nil, nil, err
			}
			return data, options, nil
		}
	}
	for _, option := range options {
		if _, diagnostic := option.(diagnosticChildOption); !diagnostic {
			continue
		}
		expanded := expandGeneratedDecodeOptions(options)
		if len(expanded) != len(options) && len(expanded) != 0 {
			if probe, ok := expanded[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
				return data, options, nil
			}
		}
		break
	}
	if len(options) != 0 {
		if probe, ok := options[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
			return data, options, nil
		}
		if context, ok := options[0].(*generatedDecodeOption); ok {
			if context == nil || context.source == nil {
				return nil, nil, fmt.Errorf("%w: invalid generated BER decode context", ErrInvalidValue)
			}
			if context.source.light {
				if err := ValidateBERElement(data, options...); err != nil {
					return nil, nil, err
				}
				return data, options, nil
			}
			if context.source.validElement(data) {
				if err := ValidateBERElement(data, options...); err != nil {
					return nil, nil, err
				}
				return data, options, nil
			}
			if _, within := berSubsliceOffset(context.source.owned, data); within {
				return nil, nil, fmt.Errorf("%w: generated BER child is not a validated element", ErrInvalidValue)
			}
			if err := ValidateBERElement(data, options...); err != nil {
				return nil, nil, err
			}
			if context.pending == nil || !sameBERSlice(context.pending.input, data) {
				return nil, nil, fmt.Errorf("%w: reconstructed BER input has not passed preflight", ErrInvalidValue)
			}
			source := context.pending
			source.owned = data
			source.input = nil
			source.reconstructed = true
			detached := *context
			detached.source = source
			detached.pending = nil
			detachedOptions := append([]DecodeOption(nil), options...)
			detachedOptions[0] = &detached
			return source.owned, detachedOptions, nil
		}
	}
	// A root indefinite length is known before the scan starts, so its
	// boundaries can be recorded in that same pass. A nested indefinite
	// length or deep construction is discovered during the pass and gets a
	// second proof pass only when needed.
	for _, option := range options {
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.lightInput == nil && len(data) > 1 && !hasGeneratedMode(options, generatedModeLight) {
			if rootHasIndefiniteLength(data) {
				form.state.proofNeeded = true
			}
			break
		}
	}
	if err := ValidateBERElement(data, options...); err != nil {
		return nil, nil, err
	}
	if len(options) == 1 {
		if form, ok := options[0].(berFormOption); ok && form.state != nil && !form.state.proofNeeded {
			form.state.lightInput = data
			config, _ := decodeOptions(options)
			return compactLightDecodeInput(data, options, config)
		}
	}
	for _, option := range options {
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.lightInput != nil {
			return data, options, nil
		}
	}
	config, err := decodeOptions(options)
	if err != nil {
		return nil, nil, err
	}
	if config.generatedMode == generatedModeProof && (config.form == nil || !sameBERSlice(config.form.owned, data)) {
		return nil, nil, fmt.Errorf("%w: generated BER input has not been owned", ErrInvalidValue)
	}
	if config.form != nil && !config.form.proofNeeded {
		if config.form.lightInput == nil {
			config.form.lightInput = data
		}
		return compactLightDecodeInput(data, options, config)
	}
	if config.form != nil && config.form.validated == nil {
		if !sameBERSlice(config.form.lightOwned, data) {
			data = bytes.Clone(data)
		}
		config.form.owned = data
		// The first scan already published tolerant findings. A second scan
		// records boundaries for the proof without publishing them again or
		// spending the first scan's diagnostic budget a second time.
		proofConfig := config
		proofConfig.violations = new(ViolationLog)
		proofConfig.reportScope = new(reportScope)
		proofOption := decodeOptionFunc(func(resolved *decodeConfig) error {
			*resolved = proofConfig
			return nil
		})
		if err := ValidateBERElement(data, proofOption); err != nil {
			return nil, nil, err
		}
	}
	if config.form == nil || config.form.validated == nil || !sameBERSlice(config.form.validated.input, data) {
		return nil, nil, fmt.Errorf("%w: generated BER input has not passed preflight", ErrInvalidValue)
	}
	source := config.form.validated
	if source.owned == nil {
		if sameBERSlice(config.form.owned, data) {
			source.owned = data
		} else {
			source.owned = append([]byte(nil), data...)
		}
		source.replay = &ReplayState{}
		source.input = nil
		config.form.owned = nil
	}
	root := new(generatedDecodeContextStorage)
	context := &root.context
	*context = generatedDecodeOption{source: source, config: config, validated: true}
	if config.hasPath {
		context.pathOptions = options
	}
	root.options[0] = context
	return source.owned, root.options[:], nil
}

// compactLightDecodeInput retains resolved options and linked paths without
// issuing a validated-span proof. Every child still runs the ordinary X.690
// (02/2021) §§8.1.3, 8.7 structural checks and Q.773 (06/1997) §4.1.1 scan.
func compactLightDecodeInput(data []byte, options []DecodeOption, config decodeConfig) ([]byte, []DecodeOption, error) {
	state := config.form
	if state.lightOwned == nil {
		state.lightOwned = bytes.Clone(data)
	}
	// A canonical decode, or explicit capture suppression, needs no replay
	// state. The first captured child creates the shared state on demand.
	input := new(lightGeneratedDecodeInput)
	source, context := &input.source, &input.context
	*source = validatedBERSource{light: true, input: data, owned: state.lightOwned, replay: state.lightReplay}
	*context = generatedDecodeOption{source: source, config: config, validated: true}
	if config.hasPath {
		context.pathOptions = options
	}
	input.options[0] = context
	return data, input.options[:], nil
}

// The working source and its first context have the same decode lifetime.
type lightGeneratedDecodeInput struct {
	source validatedBERSource
	generatedDecodeContextStorage
}

// A decode context and singleton option list share one call lifetime.
type generatedDecodeContextStorage struct {
	context generatedDecodeOption
	options [1]DecodeOption
}

func rootHasIndefiniteLength(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	lengthOffset := 1
	if data[0]&0x1f == 0x1f {
		_, tagLength, err := DecodeTag(data)
		if err != nil {
			return false
		}
		lengthOffset = tagLength
	}
	return lengthOffset < len(data) && data[lengthOffset] == 0x80
}

func hasGeneratedMode(options []DecodeOption, mode generatedDecodeMode) bool {
	for _, option := range options {
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.resolved != nil && form.state.resolved.config.generatedMode == mode {
			return true
		}
		if selected, ok := option.(generatedModeOption); ok && selected.mode == mode {
			return true
		}
	}
	return false
}

func (source *validatedBERSource) validElement(data []byte) bool {
	if source == nil {
		return false
	}
	offset, ok := berSubsliceOffset(source.owned, data)
	end, exists := source.spanEnd(offset)
	return ok && exists && end == offset+len(data)
}

func (source *validatedBERSource) matchesValidated(data []byte) bool {
	if source == nil {
		return false
	}
	offset, ok := berSubsliceOffset(source.owned, data)
	if !ok || offset > len(source.validated) {
		return false
	}
	if len(data) > len(source.validated)-offset {
		return false
	}
	return bytes.Equal(data, source.validated[offset:offset+len(data)])
}

func (source *validatedBERSource) spanEnd(offset int) (int, bool) {
	if source.shortSpans != nil {
		if offset < 0 || offset >= len(source.shortSpans) {
			return 0, false
		}
		end := source.shortSpans[offset]
		return int(end), end != 0
	}
	end, exists := source.spans[offset]
	return end, exists
}

// decodeValidatedTLV checks the current bytes against the private preflight
// copy before using a recorded boundary. It scans changed bytes, then parses
// the current prefix. X.690 (02/2021) §8.1.3.6 includes EOC in an indefinite
// TLV, while its contents exclude those two octets.
func decodeValidatedTLV(data []byte, context *generatedDecodeOption, form *berFormState) (tag.Tag, int, []byte, error, bool) {
	if context.source != nil && context.source.light {
		return tag.Tag{}, 0, nil, nil, false
	}
	if context.source == nil {
		return tag.Tag{}, 0, nil, fmt.Errorf("%w: invalid generated BER decode context", ErrInvalidValue), true
	}
	offset, within := berSubsliceOffset(context.source.owned, data)
	if !within {
		return tag.Tag{}, 0, nil, nil, false
	}
	end, exists := context.source.spanEnd(offset)
	if !exists {
		return tag.Tag{}, 0, nil, fmt.Errorf("%w: BER prefix is not a validated element", ErrInvalidValue), true
	}
	if !context.source.matchesValidated(data) {
		if err := ValidateBERElement(data, context); err != nil {
			return tag.Tag{}, 0, nil, err, true
		}
	}
	decodedTag, total, contents, err := decodeTLV(data, context.config.limits, form)
	if err != nil {
		return tag.Tag{}, 0, nil, err, true
	}
	if total != end-offset {
		return tag.Tag{}, 0, nil, ErrInvalidLength, true
	}
	return decodedTag, total, contents, nil, true
}

func sameBERSlice(first, second []byte) bool {
	return len(first) == len(second) && len(first) != 0 && unsafe.SliceData(first) == unsafe.SliceData(second)
}

func berSubsliceOffset(root, child []byte) (int, bool) {
	if len(root) == 0 || len(child) == 0 {
		return 0, false
	}
	start := uintptr(unsafe.Pointer(unsafe.SliceData(root)))
	position := uintptr(unsafe.Pointer(unsafe.SliceData(child)))
	if position < start {
		return 0, false
	}
	offset := position - start
	if offset > uintptr(len(root)) || uintptr(len(child)) > uintptr(len(root))-offset {
		return 0, false
	}
	return int(offset), true
}

// CaptureGeneratedBERReplay retains a view of the mode's working copy.
// Reconstructed IMPLICIT tags have no received subrange and get a separate
// copy; their enclosing received element remains replay authority.
func CaptureGeneratedBERReplay(data []byte, options []DecodeOption) *ReplayNode {
	if !ReplayCaptureEnabled(options) {
		return nil
	}
	for _, option := range options {
		if child, ok := option.(diagnosticChildOption); ok {
			return CaptureGeneratedBERReplay(data, child.options)
		}
		context, ok := option.(*generatedDecodeOption)
		if !ok || context == nil || context.source == nil {
			continue
		}
		if context.source.light && context.source.replay == nil {
			context.source.replay = new(ReplayState)
			if context.config.form != nil {
				context.config.form.lightReplay = context.source.replay
			}
		}
		if context.source.replay == nil {
			continue
		}
		original := data
		_, owned := berSubsliceOffset(context.source.owned, data)
		if !owned && context.source.light {
			// Prepare also supports callers without the ownership wrapper.
			// Their received slices map into the private, equal-length copy.
			if offset, received := berSubsliceOffset(context.source.input, data); received {
				original = context.source.owned[offset : offset+len(data)]
				owned = true
			}
		}
		if !owned {
			original = append([]byte(nil), data...)
		}
		node := &ReplayNode{state: context.source.replay, original: original}
		if context.config.tolerant {
			node.profileReplaySafe = replayProfileSafe(data, context.config, node)
		}
		context.source.replay.nodeCount++
		if owned && !context.source.reconstructed && sameBERSlice(original, context.source.owned) {
			context.source.replay.root = node
		}
		if owned && !context.source.reconstructed {
			if wireTag, _, err := DecodeTag(data); err == nil {
				node.wireTag, node.wireTagKnown = wireTag, true
			}
		}
		return node
	}
	for _, option := range options {
		form, ok := option.(berFormOption)
		if !ok || form.state == nil || form.state.lightInput == nil {
			continue
		}
		state := form.state
		if state.lightReplay == nil {
			state.lightReplay = new(ReplayState)
			if state.lightOwned == nil {
				state.lightOwned = bytes.Clone(state.lightInput)
			}
		}
		var original []byte
		offset, received := berSubsliceOffset(state.lightInput, data)
		if received {
			original = state.lightOwned[offset : offset+len(data)]
		} else {
			original = bytes.Clone(data)
		}
		node := &ReplayNode{state: state.lightReplay, original: original}
		if config, err := decodeOptions(options); err == nil && config.tolerant {
			node.profileReplaySafe = replayProfileSafe(data, config, node)
		}
		state.lightReplay.nodeCount++
		// X.690 (02/2021) §8.14: an IMPLICIT child can have a
		// reconstructed universal tag that was never received on the wire.
		if received {
			if wireTag, _, err := DecodeTag(data); err == nil {
				node.wireTag, node.wireTagKnown = wireTag, true
			}
		}
		state.lastCaptured = node
		return node
	}
	return nil
}

// CompleteGeneratedBERDecode retains a detached typed baseline in all modes.
// A generated comparator avoids a comparison stream when it can prove equality.
// Unknown values without a source proof prepare it here so first replay needs
// only a current pass.
func CompleteGeneratedBERDecode[T any](options []DecodeOption, value *T, encode func(*T, ...EncodeOption) ([]byte, error), comparators ...func(*T, *T, *BERReplayComparisons) int) error {
	var replay *ReplayState
	var tolerant bool
	var light bool
	var lightRoot *ReplayNode
	for _, option := range options {
		context, ok := option.(*generatedDecodeOption)
		if ok && context != nil && context.parent == nil && context.source != nil {
			// A light root is completed only after its own capture. A lone
			// child capture does not establish a received root range.
			if context.source.light && (context.source.replay == nil || context.source.replay.root == nil) {
				continue
			}
			replay = context.source.replay
			tolerant = context.config.tolerant
			if context.source.light && context.source.replay != nil {
				light = true
				lightRoot = context.source.replay.root
			}
		}
		if form, ok := option.(berFormOption); ok && form.state != nil && form.state.lastCaptured != nil {
			state := form.state
			if sameBERSlice(state.lastCaptured.original, state.lightOwned) {
				replay = state.lightReplay
				light = true
				lightRoot = state.lastCaptured
				replay.root = lightRoot
				config, err := decodeOptions(options)
				if err != nil {
					return err
				}
				tolerant = config.tolerant
			}
		}
	}
	if replay == nil {
		return nil
	}
	if len(comparators) != 0 {
		config, err := decodeOptions(options)
		if err != nil {
			return err
		}
		if config.checkReplayComparator {
			original := comparators[0]
			comparators = []func(*T, *T, *BERReplayComparisons) int{func(a, b *T, nodes *BERReplayComparisons) int {
				if err := CheckBERReplayComparatorForTesting(a, b, func(n *BERReplayComparisons) int { return original(a, b, n) }); err != nil {
					panic(err)
				}
				return original(a, b, nodes)
			}}
			copied, err := CloneBERValue(value)
			if err != nil {
				return err
			}
			comparators[0](value, copied.(*T), nil)
		}
	}
	if tolerant {
		config, err := decodeOptions(options)
		if err != nil {
			return err
		}
		if config.violations != nil {
			// Children have committed into this private root stage. A clean
			// tolerant decode proved the same rules as a strict decode; prior
			// reports in the caller's destination are outside this operation.
			config.violations.mu.Lock()
			tolerant = len(config.violations.records) != 0
			config.violations.mu.Unlock()
		}
	}
	replay.decodeTolerant = tolerant
	if tolerant {
		config, err := decodeOptions(options)
		if err != nil {
			return err
		}
		if config.reportScope != nil {
			replay.profileIndex = config.reportScope.replayProfile
		}
	}
	replay.generatedComparison = len(comparators) != 0
	if light && len(comparators) == 0 {
		// Decoded byte fields can borrow from the working input that also
		// backs received replay octets. Detach the returned value before a
		// caller can edit a field in place and corrupt those octets.
		baselineValue := *value
		copyValue, err := CloneBERValue(value)
		if err != nil {
			return err
		}
		*value = *copyValue.(*T)
		collector := newReplayCollector(len(lightRoot.original))
		baseline, err := encode(value, replayModeOption{state: replay, baseline: true, collector: collector})
		if err != nil {
			replay.disabled = true
			return nil
		}
		if collector.finish(baseline) != nil {
			// Replay bookkeeping is optional. A valid decode still returns its
			// value if the encoder cannot identify a received child position.
			replay.disabled = true
			return nil
		}
		replay.baselineBytes = baseline
		replay.baselineNodes = collector.nodes
		replay.eagerBaseline = true
		replay.same = func(current any, nodeValues *BERReplayComparisons) berValueComparison {
			return compareBERValueNodes(reflect.ValueOf(current), reflect.ValueOf(&baselineValue), 0, nodeValues)
		}
		return nil
	}
	// The typed decoder may have borrowed primitive contents from the
	// input. Keep its tree as the immutable baseline and give the caller an
	// independent tree before either can be mutated.
	baseline := *value
	copyValue, err := CloneBERValue(value)
	if err != nil {
		return err
	}
	*value = *copyValue.(*T)
	var proof BERReplayComparisons
	proof.proofOnly = true
	if len(comparators) != 0 && comparators[0](value, &baseline, &proof) == int(berValueUnknown) && !proof.sourceEqual && replay.root != nil {
		collector := newReplayCollector(len(replay.root.original))
		encoded, err := encode(&baseline, replayModeOption{state: replay, baseline: true, collector: collector})
		if err != nil || collector.finish(encoded) != nil {
			replay.disabled = true
			return nil
		}
		replay.baselineBytes, replay.baselineNodes, replay.eagerBaseline = encoded, collector.nodes, true
	} else {
		replay.setBaseline(func(mode EncodeOption) ([]byte, error) { return encode(&baseline, mode) })
	}
	replay.same = func(current any, nodeValues *BERReplayComparisons) berValueComparison {
		if len(comparators) != 0 {
			return berValueComparison(comparators[0](current.(*T), &baseline, nodeValues))
		}
		return compareBERValueNodes(reflect.ValueOf(current), reflect.ValueOf(&baseline), 0, nodeValues)
	}
	return nil
}
