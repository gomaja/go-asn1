package ber

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// ConstraintViolation describes a decoded abstract value outside its ASN.1
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

type encodeConfig struct{ tolerant bool }

// ToleranceOption is the single opt-in policy shared by generated BER
// decoders and encoders.
type ToleranceOption interface {
	DecodeOption
	EncodeOption
}

type toleranceOption struct {
	violations *ViolationLog
}

// ViolationLog collects constraint violations from concurrent BER decodes.
// Snapshot returns an independent copy in append order. A zero value is ready
// for use; callers may share one log across decode calls.
type ViolationLog struct {
	mu      sync.Mutex
	records []ConstraintViolation
}

func (log *ViolationLog) append(record ConstraintViolation) {
	log.mu.Lock()
	log.records = append(log.records, record)
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

// WithConstraintTolerance admits out-of-constraint BER values. Decoding records
// each violation in reports, which may be shared across concurrent decoders.
// Encoding requires an explicit tolerance option; it may use a different log.
// Original BER bytes are kept with the decoded value and used only while its
// typed contents remain unchanged; modified values encode from their current
// fields. The report destination must be non-nil. Tolerance covers only values
// representable in the generated int64 or uint64 field. An unrepresentable
// INTEGER returns ErrInvalidValue and records no violation (ITU-T X.680
// (02/2021) §§49.7, 50–51).
func WithConstraintTolerance(reports *ViolationLog) ToleranceOption {
	return &toleranceOption{violations: reports}
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

// CheckEncodedLength enforces a generated SIZE check unless encoding is tolerant.
func CheckEncodedLength(options []EncodeOption, path, constraint string, observed int) error {
	length := observed
	return checkEncodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedLength: &length})
}

// CheckEncodedValue enforces a generated value-set check unless encoding is tolerant.
func CheckEncodedValue(options []EncodeOption, path, constraint, observed string) error {
	return checkEncodedConstraint(options, ConstraintViolation{Path: path, Constraint: constraint, ObservedValue: observed})
}

func checkEncodedConstraint(options []EncodeOption, violation ConstraintViolation) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if config.tolerant {
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

// ChildDecodeOptions qualifies violations reported by a nested BER decoder.
func ChildDecodeOptions(options []DecodeOption, component string) []DecodeOption {
	child := append([]DecodeOption(nil), options...)
	child = append(child, constraintPathOption(component))
	return child
}

// ConstraintToleranceEnabled reports whether a validated decode option set
// requested constraint tolerance.
func ConstraintToleranceEnabled(options []DecodeOption) bool {
	config, err := decodeOptions(options)
	return err == nil && config.tolerant
}

// PreserveEncodedBER returns the original BER when the current typed value
// still encodes to its decode-time snapshot. X.690 (02/2021) §8.1.3 permits
// multiple length forms, so reconstructing a value can change valid BER bytes.
func PreserveEncodedBER(encoded, original, snapshot []byte, options []EncodeOption) []byte {
	config, err := encodeOptions(options)
	if err == nil && config.tolerant && original != nil && bytes.Equal(encoded, snapshot) {
		return append([]byte(nil), original...)
	}
	return encoded
}
