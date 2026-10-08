package ber

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// ConstraintViolation describes an encoded or decoded abstract value outside its ASN.1
// permitted set. ITU-T X.680 (02/2021) §§49.7, 50.1, 51.2.2, 51.4.2, 51.5.3.
type ConstraintViolation struct {
	Path           string
	Constraint     string
	ObservedLength *int
	ObservedValue  string
}

// ConstraintError is returned by a strict BER codec for a value outside its
// permitted set. A caller can inspect it with errors.As.
type ConstraintError struct{ ConstraintViolation }

func (e *ConstraintError) Error() string {
	if e.ObservedLength != nil {
		return fmt.Sprintf("%s length %d violates %s", e.Path, *e.ObservedLength, e.Constraint)
	}
	return fmt.Sprintf("%s value %s violates %s", e.Path, e.ObservedValue, e.Constraint)
}

// EncodeOption configures a generated BER encoder.
type EncodeOption interface{ applyEncode(*encodeConfig) error }

type encodeConfig struct {
	tolerant   bool
	violations *ViolationLog
	path       string
}

// ToleranceOption is the single opt-in policy shared by generated BER
// decoders and encoders.
type ToleranceOption interface {
	DecodeOption
	EncodeOption
}

type toleranceOption struct {
	violations *ViolationLog
}

// ViolationLog collects constraint violations from concurrent BER codecs.
// Snapshot returns an independent copy in append order. A zero value is ready
// for use; callers may share one log across codec calls.
type ViolationLog struct {
	mu      sync.Mutex
	records []ConstraintViolation
}

func (log *ViolationLog) append(record ConstraintViolation) {
	log.mu.Lock()
	log.records = append(log.records, record)
	log.mu.Unlock()
}

func (log *ViolationLog) appendBatch(records []ConstraintViolation) {
	log.mu.Lock()
	log.records = append(log.records, records...)
	log.mu.Unlock()
}

// Snapshot returns the reports collected so far without exposing the log's storage.
func (log *ViolationLog) Snapshot() []ConstraintViolation {
	log.mu.Lock()
	defer log.mu.Unlock()
	snapshot := make([]ConstraintViolation, len(log.records))
	copy(snapshot, log.records)
	for i := range snapshot {
		if snapshot[i].ObservedLength != nil {
			length := *snapshot[i].ObservedLength
			snapshot[i].ObservedLength = &length
		}
	}
	return snapshot
}

// Reset discards all reports collected so far.
func (log *ViolationLog) Reset() {
	log.mu.Lock()
	log.records = nil
	log.mu.Unlock()
}

// WithConstraintTolerance admits out-of-constraint BER values. A generated
// decode or encode call publishes its violations to reports only when that
// call succeeds. Failed calls publish nothing. The log may be shared across
// concurrent codecs.
// Received BER bytes are kept only when a valid noncanonical form or a
// tolerated constraint violation would otherwise change on re-encoding, and
// only while the typed contents remain unchanged. Modified values encode from
// their current fields; DER always encodes from the typed value. The report
// destination must be non-nil. Tolerance covers only values
// representable in the generated int64 or uint64 field. An unrepresentable
// INTEGER returns ErrInvalidValue and records no violation (ITU-T X.680
// (02/2021) §§49.7, 50–51).
func WithConstraintTolerance(reports *ViolationLog) ToleranceOption {
	return &toleranceOption{violations: reports}
}

// StageDecodeReports gives a generated decoder a private report destination.
// Its finish function publishes the staged reports only on success. Nested
// generated calls commit into the parent's private destination.
func StageDecodeReports(options []DecodeOption) ([]DecodeOption, func(bool)) {
	staged := append([]DecodeOption(nil), options...)
	var commits []func(bool)
	for i, option := range staged {
		tolerance, ok := option.(*toleranceOption)
		if !ok || tolerance == nil || tolerance.violations == nil {
			continue
		}
		destination := tolerance.violations
		var pending ViolationLog
		staged[i] = &toleranceOption{violations: &pending}
		commits = append(commits, func(success bool) {
			if success {
				destination.appendBatch(pending.Snapshot())
			}
		})
	}
	return staged, func(success bool) {
		for _, commit := range commits {
			commit(success)
		}
	}
}

// StageEncodeReports is the encoder counterpart of StageDecodeReports.
func StageEncodeReports(options []EncodeOption) ([]EncodeOption, func(bool)) {
	staged := append([]EncodeOption(nil), options...)
	var commits []func(bool)
	for i, option := range staged {
		tolerance, ok := option.(*toleranceOption)
		if !ok || tolerance == nil || tolerance.violations == nil {
			continue
		}
		destination := tolerance.violations
		var pending ViolationLog
		staged[i] = &toleranceOption{violations: &pending}
		commits = append(commits, func(success bool) {
			if success {
				destination.appendBatch(pending.Snapshot())
			}
		})
	}
	return staged, func(success bool) {
		for _, commit := range commits {
			commit(success)
		}
	}
}

func (option *toleranceOption) applyDecode(config *decodeConfig) error {
	if option.violations == nil {
		return fmt.Errorf("%w: nil BER constraint report destination", ErrInvalidValue)
	}
	if config.tolerant {
		return fmt.Errorf("%w: duplicate BER constraint tolerance option", ErrInvalidValue)
	}
	config.tolerant = true
	config.violations = option.violations
	return nil
}

func (option *toleranceOption) applyEncode(config *encodeConfig) error {
	if option.violations == nil {
		return fmt.Errorf("%w: nil BER constraint report destination", ErrInvalidValue)
	}
	if config.tolerant {
		return fmt.Errorf("%w: duplicate BER constraint tolerance option", ErrInvalidValue)
	}
	config.tolerant = true
	config.violations = option.violations
	return nil
}

func encodeOptions(options []EncodeOption) (encodeConfig, error) {
	var config encodeConfig
	for _, option := range options {
		if option == nil {
			return config, fmt.Errorf("%w: nil BER encode option", ErrInvalidValue)
		}
		if err := option.applyEncode(&config); err != nil {
			return config, err
		}
	}
	return config, nil
}

// ValidateEncodeOptions rejects malformed options even for unconstrained values.
func ValidateEncodeOptions(options ...EncodeOption) error {
	_, err := encodeOptions(options)
	return err
}

// CheckDecodedLength enforces a generated SIZE check or records its violation.
func CheckDecodedLength(options []DecodeOption, path, constraint string, observed int) error {
	length := observed
	return checkDecodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedLength: &length})
}

// CheckDecodedValue enforces a generated value-set check or records its violation.
func CheckDecodedValue(options []DecodeOption, path, constraint, observed string) error {
	return checkDecodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedValue: observed})
}

func checkDecodedConstraint(options []DecodeOption, violation ConstraintViolation) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	if config.path != "" {
		violation.Path = strings.Join([]string{config.path, violation.Path}, ".")
	}
	if !config.tolerant {
		return &ConstraintError{violation}
	}
	config.violations.append(violation)
	return nil
}

// CheckEncodedLength enforces a generated SIZE check or records its violation.
func CheckEncodedLength(options []EncodeOption, path, constraint string, observed int) error {
	length := observed
	return checkEncodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedLength: &length})
}

// CheckEncodedValue enforces a generated value-set check or records its violation.
func CheckEncodedValue(options []EncodeOption, path, constraint, observed string) error {
	return checkEncodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedValue: observed})
}

func checkEncodedConstraint(options []EncodeOption, violation ConstraintViolation) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if config.path != "" {
		violation.Path = strings.Join([]string{config.path, violation.Path}, ".")
	}
	if config.tolerant {
		config.violations.append(violation)
		return nil
	}
	return &ConstraintError{violation}
}

type constraintPathOption string

func (option constraintPathOption) applyDecode(config *decodeConfig) error {
	if strings.Contains(string(option), ".") || option == "" {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	if config.path == "" {
		config.path = string(option)
	} else {
		config.path = strings.Join([]string{config.path, string(option)}, ".")
	}
	return nil
}

func (option constraintPathOption) applyEncode(config *encodeConfig) error {
	if strings.Contains(string(option), ".") || option == "" {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	if config.path == "" {
		config.path = string(option)
	} else {
		config.path = strings.Join([]string{config.path, string(option)}, ".")
	}
	return nil
}

// ChildDecodeOptions qualifies violations reported by a nested BER decoder.
func ChildDecodeOptions(options []DecodeOption, component string) []DecodeOption {
	child := append([]DecodeOption(nil), options...)
	child = append(child, constraintPathOption(component))
	return child
}

// ChildEncodeOptions qualifies violations reported by a nested BER encoder.
func ChildEncodeOptions(options []EncodeOption, component string) []EncodeOption {
	child := append([]EncodeOption(nil), options...)
	return append(child, constraintPathOption(component))
}

// ConstraintToleranceEnabled reports whether a validated decode option set
// requested constraint tolerance.
func ConstraintToleranceEnabled(options []DecodeOption) bool {
	config, err := decodeOptions(options)
	return err == nil && config.tolerant
}

type berFormState struct{ preserve bool }

type berFormOption struct{ state *berFormState }

func (option berFormOption) applyDecode(config *decodeConfig) error {
	config.form = option.state
	return nil
}

// TrackBERForm shares one form marker across a generated value and its children.
// X.690 (02/2021) §§8.1.3, 8.7.3 and 10.2 allow BER forms that DER forbids.
func TrackBERForm(options []DecodeOption) []DecodeOption {
	for _, option := range options {
		if _, ok := option.(berFormOption); ok {
			return options
		}
	}
	tracked := append([]DecodeOption(nil), options...)
	return append(tracked, berFormOption{state: new(berFormState)})
}

// MarkBERNonCanonical records a valid BER form that a schema-aware decoder
// knows the canonical encoder will change, such as an implicit constructed string.
func MarkBERNonCanonical(options []DecodeOption) {
	for _, option := range options {
		if form, ok := option.(berFormOption); ok {
			form.state.preserve = true
			return
		}
	}
}

// BERNeedsPreservation reports whether decoding found a BER form that needs
// the received bytes for an exact unchanged-value re-encode.
func BERNeedsPreservation(options []DecodeOption) bool {
	for _, option := range options {
		if form, ok := option.(berFormOption); ok {
			return form.state.preserve
		}
	}
	return false
}

// MarkBERSetOrder preserves a BER SET when its received component order differs
// from the generated encoder's schema order, or a component is unknown. BER
// permits any component order; DER sorts by tag (X.690 (02/2021) §§8.11.2,
// 10.3). Erratum 1 (09/2021) changes only the high-tag-number figure.
// schemaPosition maps known tags to schema positions (CHOICE tags share one).
// Generated decoders remove any EXPLICIT type wrapper before calling this helper.
func MarkBERSetOrder(data []byte, schemaPosition func(tag.Tag) int, options ...DecodeOption) error {
	if schemaPosition == nil {
		return ErrInvalidValue
	}
	// Generated decoders normally pass only their form marker. Resolve that
	// directly so a schema-order SET does not allocate for every child scan.
	limits := DefaultDecodeLimits()
	var form *berFormState
	if len(options) == 1 {
		if marker, ok := options[0].(berFormOption); ok {
			form = marker.state
		} else {
			config, err := decodeOptions(options)
			if err != nil {
				return err
			}
			limits, form = config.limits, config.form
		}
	} else if len(options) != 0 {
		config, err := decodeOptions(options)
		if err != nil {
			return err
		}
		limits, form = config.limits, config.form
	}
	outer, total, contents, err := decodeTLV(data, limits, form)
	if err != nil {
		return err
	}
	if total != len(data) || !outer.Constructed {
		return ErrInvalidValue
	}
	previous := -1
	for offset := 0; offset < len(contents); {
		current, used, _, childErr := decodeTLV(contents[offset:], limits, form)
		if childErr != nil {
			return childErr
		}
		if used <= 0 || used > len(contents)-offset {
			return ErrInvalidLength
		}
		position := schemaPosition(current)
		if position < 0 || position <= previous {
			MarkBERNonCanonical(options)
			return nil
		}
		previous = position
		offset += used
	}
	return nil
}

// PreserveEncodedBER returns the original BER when the current typed value
// still encodes to its decode-time snapshot. X.690 (02/2021) §§8.1.3, 8.7.3
// permit multiple length forms and constructed string segmentations.
func PreserveEncodedBER(encoded, original, snapshot []byte, options []EncodeOption) []byte {
	_, err := encodeOptions(options)
	if err == nil && original != nil && bytes.Equal(encoded, snapshot) {
		return append([]byte(nil), original...)
	}
	return encoded
}
