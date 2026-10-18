// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/preflight_path.go; SHA-256 1d8045ea50e35e6f8754984ef1f5d85f294b4b72b50891f093ffe62d614931cd.
package ber

import (
	"errors"
	"fmt"
	"strings"
)

// preflightProbeState is active only during one diagnostic decode. The
// diagnostic result never changes the rejection from ValidateBERElement.
type preflightProbeState struct {
	active        bool
	target        *byte
	targetOptions []DecodeOption
	targetName    string
	targetDepth   int
	opaquePrefix  string
	opaqueDepth   int
}

type preflightProbeOption struct{ state *preflightProbeState }

func (o preflightProbeOption) applyDecode(c *decodeConfig) error {
	return nil
}

type preflightPathError struct {
	path  string
	cause error
}

func (e *preflightPathError) Error() string { return fmt.Sprintf("decoding %s: %v", e.path, e.cause) }

func (e *preflightPathError) Unwrap() error { return e.cause }

func (e *preflightPathError) ASN1BERPath() string { return e.path }

// DiagnosePreflight adds a generated schema path to a whole-element failure.
// The callback runs once with nested preflight disabled; generated markers
// supply the path. Its error is ignored. The original failure, including its
// ElementError and sentinel, remains the cause. X.680 (02/2021) §§25, 27–29
// define the named components.
// If a decoder cannot name an opaque or unknown position, child[n] denotes
// its zero-based BER child index; collections use element[n] at their root.
func DiagnosePreflight(err error, data []byte, options []DecodeOption, rootChild string, decode func([]DecodeOption) error) error {
	if optionErr := ValidateDecodeOptions(options...); optionErr != nil {
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
	state := &preflightProbeState{active: true}
	if located.Offset() >= 0 && located.Offset() < len(data) {
		state.target = &data[located.Offset()]
	}
	probeOptions := append([]DecodeOption{preflightProbeOption{state: state}}, options...)
	// Diagnostic decoding may reconstruct IMPLICIT aggregates. Bound that
	// optional work after preflight has already refused the input, rather
	// than copying a large rejected value just to name its schema field.
	// Larger inputs retain the exact identifier offset and BER child path.
	if len(data) <= 64<<10 {
		_ = runPreflightProbe(decode, probeOptions)
	}
	state.active = false

	path := ""
	if state.targetName != "" {
		parts := make([]string, 0, len(state.targetOptions))
		for _, option := range state.targetOptions {
			if value, ok := option.(constraintPathOption); ok {
				parts = append(parts, string(value))
			}
		}
		path = strings.Join(append(parts, state.targetName), ".")
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

// MarkPreflightTarget records a schema name only when raw begins at the exact
// identifier offset reported by ValidateBERElement. A diagnostic decoder may
// fail at an earlier sibling with the same error class; its error path is not
// evidence that it reached the preflight failure. The options carry the names
// of ancestors already traversed by the generated decoder.
func MarkPreflightTarget(options []DecodeOption, name string, raw []byte) {
	rememberDecodedElement(options, name, raw)
	options = expandGeneratedDecodeOptions(options)
	if len(options) == 0 || len(raw) == 0 {
		return
	}
	probe, ok := options[0].(preflightProbeOption)
	if !ok || probe.state == nil || !probe.state.active || probe.state.target != &raw[0] {
		return
	}
	if len(options) > probe.state.targetDepth {
		probe.state.targetOptions = options
		probe.state.targetName = name
		probe.state.targetDepth = len(options)
	}
}

// MarkPreflightElement avoids formatting a collection index during ordinary
// decoding. Only the diagnostic pass for the failing identifier needs it.
func MarkPreflightElement(options []DecodeOption, index int, raw []byte) {
	options = expandGeneratedDecodeOptions(options)
	if len(options) == 0 || len(raw) == 0 {
		return
	}
	probe, ok := options[0].(preflightProbeOption)
	if !ok || probe.state == nil || !probe.state.active || probe.state.target != &raw[0] {
		return
	}
	MarkPreflightTarget(options, fmt.Sprintf("element[%d]", index), raw)
}

// MarkPreflightOpaque records the named prefix of an opaque field containing
// the preflight failure. Remaining positions are reported as child indexes.
// It scans each opaque field once only during a failed diagnostic decode.
func MarkPreflightOpaque(options []DecodeOption, name string, raw []byte, length int) {
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
