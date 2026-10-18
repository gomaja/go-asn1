// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_encode_options.go; SHA-256 19a9f184f24f89c0662e580a3c9eae064d46741828361103d9cb368465ce256b.
package ber

import (
	"fmt"
	"reflect"
)

// generatedEncodeMarker identifies an option chain that the generated encoder
// owns for the duration of one top-level call. Descendants may extend its
// spare capacity while their parent is suspended on the same goroutine.
type generatedEncodeMarker struct{}

func (generatedEncodeMarker) applyEncode(*encodeConfig) error { return nil }

// StageGeneratedEncodeReports stages a public call once. Generated children
// share that stage; copying the entire growing option path at each depth
// would allocate quadratically in nesting depth.
func StageGeneratedEncodeReports(options []EncodeOption) ([]EncodeOption, func(bool)) {
	if len(options) == 0 {
		// Child appends must own their storage rather than sharing this root.
		return []EncodeOption{generatedEncodeMarker{}}, noReportCommit
	}
	for _, option := range options {
		if _, ok := option.(generatedEncodeMarker); ok {
			return options, noReportCommit
		}
	}
	staged, finish := StageEncodeReports(options)
	capacity := max(2, len(staged)+1)
	owned := make([]EncodeOption, len(staged), capacity)
	copy(owned, staged)
	return append(owned, generatedEncodeMarker{}), finish
}

// ChildGeneratedEncodeOptions carries a child path in the call-local option
// buffer. Parent and sibling encoders never use a child's extended slice
// concurrently, so geometric slice growth costs linear allocation overall.
func ChildGeneratedEncodeOptions(options []EncodeOption, component string) []EncodeOption {
	owned := false
	tolerant := false
	for _, option := range options {
		if _, ok := option.(generatedEncodeMarker); ok {
			owned = true
		}
		if _, ok := option.(*toleranceOption); ok {
			tolerant = true
		}
		if mode, ok := option.(replayModeOption); ok && (mode.baseline || mode.collector != nil && mode.strict && !mode.diagnostic) {
			return options
		}
	}
	if !owned {
		return ChildEncodeOptions(options, component)
	}
	if !tolerant {
		// Strict errors are qualified at every generated reference boundary.
		// There is no report path to retain on a successful encode.
		return options
	}
	return append(options, constraintPathOption(component))
}

// ChildGeneratedElementEncodeOptions formats an index only when a report path
// must be retained. Strict generated callers qualify errors as they unwind.
func ChildGeneratedElementEncodeOptions(options []EncodeOption, index int) []EncodeOption {
	owned := false
	tolerant := false
	for _, option := range options {
		if _, ok := option.(generatedEncodeMarker); ok {
			owned = true
		}
		if _, ok := option.(*toleranceOption); ok {
			tolerant = true
		}
	}
	if owned && !tolerant {
		return options
	}
	return ChildGeneratedEncodeOptions(options, fmt.Sprintf("element[%d]", index))
}

// ParentGeneratedCollectionSizeEncodeOptions marks a generated collection's
// already-checked parent SIZE without copying its entire option path.
func ParentGeneratedCollectionSizeEncodeOptions(options []EncodeOption) []EncodeOption {
	for _, option := range options {
		if _, ok := option.(generatedEncodeMarker); ok {
			return append(options, parentCollectionSizeOption{})
		}
	}
	return ParentCollectionSizeEncodeOptions(options)
}

// CanUseLinearBEREncode admits default calls and private generated child
// options. Public options retain their diagnostic/reporting encoder path.
// Comparison passes still call every child's public replay hook.
func CanUseLinearBEREncode(options []EncodeOption) bool {
	marked := false
	for _, option := range options {
		switch value := option.(type) {
		case generatedEncodeMarker:
			marked = true
		case replayModeOption:
			if value.collector != nil || value.fast != nil || value.comparison || value.baseline {
				return false
			}
		case tcapEncodeOption, encodeSourceOption, parentCollectionSizeOption:
			// These options carry the enclosing generated call's boundary.
		default:
			return false
		}
	}
	return marked || len(options) == 0
}

// ReplayGeneratedBERNode supplies an unchanged child's received octets to a
// linear encoder. The root entry point still owns the returned byte slice.
func ReplayGeneratedBERNode(node *ReplayNode, options []EncodeOption) ([]byte, bool) {
	if node == nil || node.original == nil {
		return nil, false
	}
	// Typed equality cannot prove the received form satisfies Q.773
	// (06/1997) §4.1.1 when the decode retained a tolerated violation.
	if node.state != nil && node.state.decodeTolerant {
		return nil, false
	}
	for _, option := range options {
		if _, disabled := option.(withoutBERReplayOption); disabled {
			return nil, false
		}
		if mode, ok := option.(replayModeOption); ok {
			if mode.unchanged[node] {
				return node.original, true
			}
			if mode.typed != nil {
				if comparison, _ := mode.typed.decision(reflect.ValueOf(node).Pointer()); comparison == berValueEqual {
					return node.original, true
				}
			}
		}
	}
	return nil, false
}

// BERGeneratedReplayEnabled reads the replay decision after the public entry
// point has validated options. It avoids rebuilding an encode configuration
// for every recursive generated component.
func BERGeneratedReplayEnabled(options []EncodeOption) bool {
	for _, option := range options {
		switch value := option.(type) {
		case withoutBERReplayOption:
			return false
		case replayModeOption:
			if value.collector != nil {
				return false
			}
		}
	}
	return true
}
