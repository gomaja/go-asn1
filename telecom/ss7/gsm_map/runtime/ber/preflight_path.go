// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/preflight_path.go; SHA-256 c95572f59c21cd47233ab0142a6a0d04d38067582436447851536d9b15abe32c.
package ber

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// preflightProbeState is active only during one diagnostic decode. The
// diagnostic result never changes the rejection from ValidateBERElement.
type preflightProbeState struct {
	active         bool
	target         *byte
	targetOptions  []DecodeOption
	targetName     string
	targetDepth    int
	targetOffset   int
	failureOffset  int
	targetBERDepth int
	indexes        []int
	origin         decodeOrigin
	opaquePrefix   string
	opaqueDepth    int
}

type preflightProbeOption struct{ state *preflightProbeState }

func (o preflightProbeOption) applyDecode(c *decodeConfig) error {
	return nil
}

type preflightPathError struct {
	path  string
	cause error
}

// Error formats the preflight component path and underlying diagnostic.
func (e *preflightPathError) Error() string { return fmt.Sprintf("decoding %s: %v", e.path, e.cause) }

// Unwrap returns the underlying preflight error.
func (e *preflightPathError) Unwrap() error { return e.cause }

// ASN1BERPath returns the component path assigned during preflight.
func (e *preflightPathError) ASN1BERPath() string { return e.path }

// DiagnosePreflight adds a generated schema path to a whole-element failure.
// The callback runs once with nested preflight disabled; generated markers
// supply the path. Its error is ignored. The original failure, including its
// ElementError and sentinel, remains the cause. X.680 (02/2021) §§25, 27–29
// define the named components.
// If a decoder cannot name an opaque or unknown position, child[n] denotes
// its zero-based BER child index; collections use element[n] at their root.
// Diagnostic naming work is bounded by the caller's MaxWork.
func DiagnosePreflight(err error, data []byte, options []DecodeOption, rootChild string, decode func([]DecodeOption) error) error {
	config, optionErr := decodeOptions(options)
	if optionErr != nil {
		return optionErr
	}
	var located *ElementError
	if !errors.As(err, &located) {
		return err
	}
	indexes := located.ChildIndexes()
	if len(indexes) == 0 {
		return err
	}
	// A bound child-level refusal has outer-message coordinates. Only name
	// targets when those coordinates share the diagnostic input's root.
	sameRoot := config.location == nil || sameBERSlice(config.location.rootInput(), data)
	state := &preflightProbeState{active: true, targetOffset: -1, failureOffset: located.Offset(), indexes: indexes, origin: decodeOrigin{root: data, limits: config.limits}}
	if sameRoot && located.Offset() >= 0 && located.Offset() < len(data) {
		state.target = &data[located.Offset()]
	}
	// Reuse the tolerance policy in a private operation. Retain immutable
	// caller policy and paths, but never its report ledger, locations, form or
	// validated input: probing must not publish findings or consume its budget.
	config.tolerant, config.violations, config.reportScope = false, nil, nil
	config.location, config.form, config.positionSearch = nil, nil, nil
	private := &toleranceOption{violations: new(ViolationLog), scope: new(reportScope)}
	probeOptions := []DecodeOption{preflightProbeOption{state: state}, decodeOptionFunc(func(c *decodeConfig) error {
		*c = config
		return nil
	}), private}
	if prefix := qualifyConstraintPath(options, ""); prefix != "" {
		for _, component := range strings.Split(prefix, ".") {
			probeOptions = append(probeOptions, constraintPathOption(component))
		}
	}
	if config.collectionSizeChecked {
		probeOptions = append(probeOptions, parentCollectionSizeOption{})
	}
	// Diagnostic decoding may reconstruct IMPLICIT aggregates. Bound that
	// optional work after preflight has already refused the input, rather
	// than copying a large rejected value just to name its schema field.
	// Larger inputs retain the exact identifier offset and BER child path.
	if len(data) <= 64<<10 {
		_ = runPreflightProbe(decode, probeOptions)
	}
	state.active = false

	path := ""
	if state.targetDepth != 0 {
		parts := make([]string, 0, len(state.targetOptions))
		for _, option := range state.targetOptions {
			if value, ok := option.(constraintPathOption); ok {
				parts = append(parts, string(value))
			}
		}
		if state.targetName != "" {
			parts = append(parts, state.targetName)
		}
		for _, index := range indexes[state.targetBERDepth:] {
			parts = append(parts, fmt.Sprintf("child[%d]", index))
		}
		path = strings.Join(parts, ".")
	}
	if state.opaquePrefix != "" {
		parts := []string{state.opaquePrefix}
		for _, index := range indexes[min(state.opaqueDepth, len(indexes)):] {
			parts = append(parts, fmt.Sprintf("child[%d]", index))
		}
		path = strings.Join(parts, ".")
	}
	if path == "" {
		var parts []string
		for i, index := range indexes {
			kind := "child"
			if i == 0 && rootChild == "element" {
				kind = "element"
			}
			parts = append(parts, fmt.Sprintf("%s[%d]", kind, index))
		}
		path = strings.Join(parts, ".")
	}
	if path == "" {
		return err
	}
	return &preflightPathError{path: path, cause: err}
}

// MarkPreflightTarget names the failing identifier or a received ancestor.
// Only the diagnostic probe resolves ancestry (X.690 (02/2021) §§8.1.2,
// 8.7.3, 8.23.3). A preceding sibling or a copied value cannot name the
// failure. Remaining BER descendants retain their child indexes.
func MarkPreflightTarget(options []DecodeOption, name string, raw []byte) {
	rememberDecodedElement(options, name, raw)
	if config, err := decodeOptions(options); err == nil {
		locateUTF8Reports(config, config.location, raw, name, min(1, len(raw)), options)
	}
	options = expandGeneratedDecodeOptions(options)
	if len(options) == 0 || len(raw) == 0 {
		return
	}
	probe, ok := options[0].(preflightProbeOption)
	if !ok || probe.state == nil || !probe.state.active || name == "" {
		return
	}
	state := probe.state
	offset, received := berSubsliceOffset(state.origin.root, raw)
	// Generated IMPLICIT aggregates replace only their identifier. Their
	// bound decode location maps the reconstructed contents to the received
	// input; an unrelated copy has no such location (X.690 (02/2021) §8.14.4 b)).
	if !received {
		if config, err := decodeOptions(options); err == nil && config.location != nil {
			offset, received = config.location.wireOffset(raw)
		}
	}
	if !received || state.target == nil {
		return
	}
	depth := len(state.indexes)
	if offset != state.failureOffset {
		ancestors, err := state.origin.ancestry(offset)
		if err != nil || offset != 0 && len(ancestors) == 0 || len(ancestors) >= len(state.indexes) || !slices.Equal(ancestors, state.indexes[:len(ancestors)]) {
			return
		}
		depth = len(ancestors)
	}
	if offset > state.targetOffset || offset == state.targetOffset && len(options) > state.targetDepth {
		state.targetOptions = options
		state.targetName = name
		state.targetDepth = len(options)
		state.targetOffset = offset
		state.targetBERDepth = depth
	}
}

// MarkPreflightElement records the received identifier for ordinary constraint
// locations and names a failed identifier or ancestor during a diagnostic probe.
func MarkPreflightElement(options []DecodeOption, index int, raw []byte) {
	if len(raw) == 0 {
		return
	}
	expanded := expandGeneratedDecodeOptions(options)
	if len(expanded) != 0 {
		if probe, ok := expanded[0].(preflightProbeOption); ok && probe.state != nil && probe.state.active {
			MarkPreflightTarget(expanded, fmt.Sprintf("element[%d]", index), raw)
			return
		}
	}
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil && context.config.location != nil {
			context.config.location.rememberElement(index, raw)
			if context.config.form != nil && context.config.form.mapPending != nil {
				claimMAPElement(context.config, options, fmt.Sprintf("element[%d]", index), raw)
			}
			return
		}
	}
	if config, err := decodeOptions(options); err == nil && config.location != nil {
		config.location.rememberElement(index, raw)
		if config.form != nil && config.form.mapPending != nil {
			claimMAPElement(config, options, fmt.Sprintf("element[%d]", index), raw)
		}
	}
}

// MarkPreflightOpaque records the named prefix of an opaque field containing
// the preflight failure. Remaining positions are reported as child indexes.
// A generated decode checks string contents when the message contains a
// restricted string tag, then scans the field again on a failed diagnostic decode.
func MarkPreflightOpaque(options []DecodeOption, name string, raw []byte, length int) {
	if config, err := decodeOptions(options); err == nil {
		checkGeneratedOpaqueContents(config, raw, length, options)
		excludeMAPOpaque(config, raw, length)
		locateUTF8Reports(config, config.location, raw, name, length, options)
	}
	options = expandGeneratedDecodeOptions(options)
	if len(options) == 0 {
		return
	}
	probe, ok := options[0].(preflightProbeOption)
	if !ok || probe.state == nil || !probe.state.active || probe.state.target == nil {
		return
	}
	if length < 0 || length > len(raw) {
		return
	}
	raw = raw[:length]
	state := probe.state
	var parts []string
	for _, option := range options {
		switch value := option.(type) {
		case constraintPathOption:
			parts = append(parts, string(value))
		}
	}
	found := false
	for i := range raw {
		if &raw[i] == state.target {
			found = true
			break
		}
	}
	if !found {
		return
	}
	parts = append(parts, name)
	if len(parts) > state.opaqueDepth {
		state.opaquePrefix = strings.Join(parts, ".")
		state.opaqueDepth = len(parts)
	}
}

func runPreflightProbe(decode func([]DecodeOption) error, options []DecodeOption) (err error) {
	// Malformed input is already rejected. A diagnostic pass must never turn
	// that rejection into a panic if a typed decoder assumes valid preflight.
	defer func() {
		if recover() != nil {
			err = nil
		}
	}()
	return decode(options)
}
