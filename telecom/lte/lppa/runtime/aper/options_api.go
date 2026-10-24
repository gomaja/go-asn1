// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/options_api.go; SHA-256 7c5979d01b98022fcf092eededc056fcf383254b908e4e1e47c2c7b4d9e3fdc2.
package aper

import "errors"

// DecodeOption carries per-call policy. DecodeReport state is created only
// when a call starts; TS 36.455 V19.0.0 §9.4 selects aligned BASIC-PER.
type DecodeOption struct {
	limits    Limits
	hasLimits bool
}

// WithReceiverMode selects the TS 36.455 V19.0.0 §10 receiver policy.
// Its wire tolerance set is empty: both modes enforce X.691 (02/2021).
func WithReceiverMode() DecodeOption { return DecodeOption{} }

// ApplyDecodeOptions creates independent reporting state for one operation.
func ApplyDecodeOptions(options ...DecodeOption) DecodeState {
	var settings decodeSettings
	for _, option := range options {
		if option.hasLimits {
			settings.operationLimits = option.limits
			settings.hasOperationLimits = true
		}
	}
	settings.operationLimits.MaxOutputBytes = 0
	budget, err := NewOperationBudget(settings.operationLimits)
	if err != nil {
		return DecodeState{failure: err}
	}
	budget.reading = true
	budget.outputLimited = false
	settings.callReport = &DecodeReport{}
	budget.callReport = settings.callReport
	settings.operation = budget
	return DecodeState{settings: settings}
}

// DecodeReport owns the findings of one call, including findings collected
// before a fatal error. Structural validation is a separate operation.
type DecodeReport struct {
	Deviations   []Deviation
	Observations []Observation
}

// Deviation records one innermost fatal wire error. APER accepts no deviations.
type Deviation struct {
	Location Location
	Rule     SourceRule
}

// ObservationKind distinguishes legal values outside the pinned schema.
type ObservationKind uint8

const (
	UnknownProcedure ObservationKind = iota + 1
	UnknownIE
	UnknownExtension
)

// Observation marks an opaque boundary, without certifying its unknown schema.
type Observation struct {
	Location Location
	Rule     SourceRule
	Kind     ObservationKind
}

// FinishDecode returns the per-call findings, including those before failure.
// The innermost DecodeError supplies the single occurrence; wrappers only
// qualify its path (TS 36.455 V19.0.0 §10; X.691 (02/2021) §11.2.1).
func FinishDecode(state DecodeState, err error) (DecodeReport, error) {
	options := state.settings
	report := DecodeReport{}
	if state.failure != nil && err == nil {
		err = state.failure
	}
	if options.operation != nil && options.operation.err != nil && !errors.Is(err, ErrLimit) {
		path := Path("")
		var nested *DecodeError
		if errors.As(err, &nested) {
			path = nested.Location.Path
		}
		err = OperationError(options.operation.err, path)
	}
	if options.callReport != nil {
		report = *options.callReport
	}
	if err == nil {
		return report, nil
	}
	var located *DecodeError
	if errors.As(err, &located) && located.Kind == Syntax {
		if options.operation == nil && len(report.Observations)+len(report.Deviations) >= 1024 {
			return report, &DecodeError{Kind: Limit, Location: located.Location, Rule: located.Rule, Err: ErrLimit}
		}
		if options.operation != nil {
			bb := NewBudgetBuffer(options.operation)
			if failure := bb.ChargeLocatedReport(located.Location, 0); failure != nil {
				return report, failure
			}
		}
		if options.operation == nil {
			report.Deviations = append(report.Deviations, Deviation{Location: located.Location, Rule: located.Rule})
		} else {
			next, failure := AppendValues(NewBudgetBuffer(options.operation), report.Deviations, Deviation{Location: located.Location, Rule: located.Rule})
			if failure != nil {
				return report, failure
			}
			report.Deviations = next
		}
	}
	return report, err
}

// BuildOption reserves the per-call construction policy for complete values.
type BuildOption struct {
	limits    Limits
	hasLimits bool
}

// ValidationOption reserves the per-call validation policy.
type ValidationOption struct {
	limits    Limits
	hasLimits bool
}

// EncodeOption configures complete-value encoding without exposing mutable
// bit-buffer state.
type EncodeOption struct {
	hasLimits bool
	fresh     bool
	limits    Limits
}

// WithoutReplay requests a fresh complete APER encoding of known values.
func WithoutReplay() EncodeOption { return EncodeOption{fresh: true} }

// EncodeWithoutReplay reports whether any option requests fresh encoding.
func EncodeWithoutReplay(options ...EncodeOption) bool {
	for _, option := range options {
		if option.fresh {
			return true
		}
	}
	return false
}

// WithLimits sets operational decode ceilings. The value contains no call state.
func WithLimits(limits Limits) DecodeOption { return DecodeOption{limits: limits, hasLimits: true} }

// WithEncodeLimits sets operational encoder ceilings.
func WithEncodeLimits(limits Limits) EncodeOption {
	return EncodeOption{limits: limits, hasLimits: true}
}

// WithBuildLimits sets operational builder ceilings.
func WithBuildLimits(limits Limits) BuildOption { return BuildOption{limits: limits, hasLimits: true} }

// WithValidationLimits sets operational validation ceilings.
func WithValidationLimits(limits Limits) ValidationOption {
	return ValidationOption{limits: limits, hasLimits: true}
}

// DecodeBuffer returns accounting shared by every known child and snapshot.
func DecodeBuffer(state DecodeState) *BitBuffer { return NewBudgetBuffer(state.settings.operation) }

// DecodeState belongs to one operation. Only immutable DecodeOption values are
// reusable; generated internal decoders share this private state explicitly.
type DecodeState struct {
	settings decodeSettings
	failure  error
}

// Usage returns a copy of one call's accounting, never a mutable report sink.
func (s DecodeState) Usage() DecodeUsage {
	if s.settings.operation == nil {
		return DecodeUsage{}
	}
	return NewBudgetBuffer(s.settings.operation).Usage()
}

// SetDecodeOptionsAligned attaches the state to the root buffer. Nested known
// values inherit that buffer rather than starting another operation.
func (bb *BitBuffer) SetDecodeOptionsAligned(state DecodeState) error {
	if state.failure != nil {
		var located *DecodeError
		if errors.As(state.failure, &located) && located.Kind == Limit {
			copyError := *located
			copyError.Location = Location{Spans: []BitSpan{{Start: 0, End: 0}}, HasWireLocation: true}
			return &copyError
		}
		return state.failure
	}
	if state.settings.operation != nil {
		return bb.setDecodeSettingsAligned(state.settings)
	}
	// The package-private streaming path can use stack accounting without reports.
	limits := DefaultLimits()
	return bb.setDecodeSettingsAligned(decodeSettings{operationLimits: limits, hasOperationLimits: true})
}

// NewOpaqueOpenTypeWithState starts a standalone table selection with the same
// call-owned budget as the complete-value codec.
func NewOpaqueOpenTypeWithState(data []byte, state DecodeState) (OpaqueOpenType, error) {
	if state.failure != nil {
		return OpaqueOpenType{}, state.failure
	}
	return newOpaqueOpenTypeWithSettings(data, state.settings)
}
