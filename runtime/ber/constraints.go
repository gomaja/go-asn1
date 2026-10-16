package ber

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"weak"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// MaxObservedValueBytes is the largest retained observation. Reports copy only
// this prefix, and ObservedValueLength records the full pre-cap length in bytes.
const MaxObservedValueBytes = 64

// ConstraintViolation describes an encoded or decoded abstract value outside its ASN.1
// permitted set. ITU-T X.680 (02/2021) §§49.7, 50.1, 51.2.2, 51.4.2, 51.5.3.
type ConstraintViolation struct {
	Path                string
	Constraint          string
	ObservedLength      *int
	ObservedValue       string
	ObservedValueLength int // bytes in the full observation before the 64-byte cap
	// OctetOffset is the zero-based offset in the concatenated string contents
	// for a wire-text violation; nil means the check has no octet location.
	OctetOffset  *int
	scope        *reportScope
	source       weak.Pointer[byte]
	preflight    bool
	observedHash [32]byte
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
	tolerant              bool
	noReplay              bool
	violations            *ViolationLog
	reportScope           *reportScope
	hasPath               bool
	collectionSizeChecked bool
}

// ToleranceOption is the single opt-in policy shared by generated BER
// decoders and encoders.
type ToleranceOption interface {
	DecodeOption
	EncodeOption
}

type toleranceOption struct {
	violations *ViolationLog
	scope      *reportScope
}

// ViolationLog collects constraint violations from concurrent BER codecs.
// Repeated reports of the same violation in a staged codec call are idempotent.
// Snapshot returns an independent copy in first-report order. A zero value is
// ready for use; separate staged codec calls retain separate histories.
type ViolationLog struct {
	mu      sync.Mutex
	records []ConstraintViolation
	scope   *reportScope
	seen    map[violationKey]int
	wire    map[wireViolationKey]int
}

// A ledger is private to one operation and shared by nested stages. It counts
// unique reports before publication, so preflight/typed reconciliation costs
// one budget unit even when those passes write into different pending logs.
type reportScope struct {
	mu            sync.Mutex
	ledger        ViolationLog
	observedBytes int
}

func (scope *reportScope) reserve(record ConstraintViolation, limits DiagnosticLimits) error {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if index, exists := scope.ledger.findLocked(record); exists {
		scope.ledger.replaceLocked(index, record)
		return nil
	}
	if limits.MaxRecords != 0 && len(scope.ledger.records) >= limits.MaxRecords {
		return fmt.Errorf("%w: BER diagnostic record limit exceeded", ErrResourceLimit)
	}
	size := len(record.ObservedValue)
	// Subtraction precedes addition, keeping the byte counter within its limit.
	if limits.MaxObservedBytes != 0 && size > limits.MaxObservedBytes-scope.observedBytes {
		return fmt.Errorf("%w: BER diagnostic observed-byte limit exceeded", ErrResourceLimit)
	}
	scope.ledger.appendLocked(record)
	if limits.MaxObservedBytes != 0 {
		scope.observedBytes += size
	}
	return nil
}

type violationKey struct {
	scope            *reportScope
	path, constraint string
	source           weak.Pointer[byte]
	offset           int
	observed         [32]byte
	length           int
	hasLength        bool
}

type wireViolationKey struct {
	scope      *reportScope
	constraint string
	source     weak.Pointer[byte]
	offset     int
}

func reportKey(record ConstraintViolation) violationKey {
	key := violationKey{scope: record.scope, path: record.Path, constraint: record.Constraint, source: record.source, offset: -1}
	if record.OctetOffset != nil {
		key.offset = *record.OctetOffset
	} else {
		// Abstract-value checks have no received octet. Keep distinct observed
		// values and lengths rather than treating an unknown location as zero.
		key.observed = record.observedHash
		if record.ObservedLength != nil {
			key.length, key.hasLength = *record.ObservedLength, true
		}
	}
	return key
}

func (log *ViolationLog) append(record ConstraintViolation, limits DiagnosticLimits) error {
	// Hash before copying the bounded observation. Distinct long abstract values
	// that share a prefix still have distinct keys without retaining their tails.
	record.observedHash = sha256.Sum256([]byte(record.ObservedValue))
	record.ObservedValueLength = len(record.ObservedValue)
	record.ObservedValue = strings.Clone(record.ObservedValue[:min(len(record.ObservedValue), MaxObservedValueBytes)])
	if record.scope != nil {
		if err := record.scope.reserve(record, limits); err != nil {
			return err
		}
	}
	log.mu.Lock()
	if record.scope == nil {
		record.scope = log.scope
	}
	if log.scope == nil {
		log.records = append(log.records, publishedViolation(record))
	} else {
		log.appendLocked(record)
	}
	log.mu.Unlock()
	return nil
}

func (log *ViolationLog) appendBatch(records []ConstraintViolation) {
	log.mu.Lock()
	for _, record := range records {
		if log.scope == nil {
			log.records = append(log.records, publishedViolation(record))
		} else {
			log.appendLocked(record)
		}
	}
	log.mu.Unlock()
}

// Public histories carry no operation ledger or input identity. Only private
// pending stages need those keys, and their weak identities never keep input
// buffers reachable, even when a caller retains staged options after finish.
func publishedViolation(record ConstraintViolation) ConstraintViolation {
	record.scope = nil
	record.source = weak.Pointer[byte]{}
	record.observedHash = [32]byte{}
	record.preflight = false
	return record
}

func (log *ViolationLog) findLocked(record ConstraintViolation) (int, bool) {
	if index, exists := log.seen[reportKey(record)]; exists {
		return index, true
	}
	if record.source != (weak.Pointer[byte]{}) && record.OctetOffset != nil {
		wireKey := wireViolationKey{record.scope, record.Constraint, record.source, *record.OctetOffset}
		if index, exists := log.wire[wireKey]; exists && (record.preflight || log.records[index].preflight) {
			return index, true
		}
	}
	return 0, false
}

func (log *ViolationLog) replaceLocked(index int, record ConstraintViolation) {
	if log.records[index].preflight && !record.preflight {
		// Schema-free preflight knows only the enclosing path. Upgrade it with the
		// typed field path for the same received string and octet. Never reconcile
		// two different typed paths through a provisional preflight key.
		delete(log.seen, reportKey(log.records[index]))
		log.records[index] = record
		log.seen[reportKey(record)] = index
	}
}

func (log *ViolationLog) appendLocked(record ConstraintViolation) {
	if index, exists := log.findLocked(record); exists {
		log.replaceLocked(index, record)
		return
	}
	if log.seen == nil {
		log.seen = make(map[violationKey]int)
	}
	if record.source != (weak.Pointer[byte]{}) && record.OctetOffset != nil {
		wireKey := wireViolationKey{record.scope, record.Constraint, record.source, *record.OctetOffset}
		if log.wire == nil {
			log.wire = make(map[wireViolationKey]int)
		}
		log.wire[wireKey] = len(log.records)
	}
	log.seen[reportKey(record)] = len(log.records)
	log.records = append(log.records, record)
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
		if snapshot[i].OctetOffset != nil {
			offset := *snapshot[i].OctetOffset
			snapshot[i].OctetOffset = &offset
		}
	}
	return snapshot
}

// Reset discards all reports collected so far.
func (log *ViolationLog) Reset() {
	log.mu.Lock()
	log.records = nil
	log.seen = nil
	log.wire = nil
	log.mu.Unlock()
}

// WithConstraintTolerance admits out-of-constraint BER values. A generated
// decode or encode call publishes its violations to reports only when that
// call succeeds. Failed calls publish nothing. The log may be shared across
// concurrent codecs.
// Each direct runtime call starts a fresh report scope, even when it reuses
// this option. Generated codecs use staging to share one scope across the
// preflight and typed passes and all nested calls in one outer operation.
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

func noReportCommit(bool) {}

// StageDecodeReports gives a generated decoder a private report destination.
// Its finish function publishes the staged reports only on success. Nested
// generated calls commit into the parent's private destination.
func StageDecodeReports(options []DecodeOption) ([]DecodeOption, func(bool)) {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			return options, noReportCommit
		}
		if diagnostic, ok := options[0].(diagnosticChildOption); ok {
			if !decodeToleranceNeedsStaging(diagnostic.options) {
				return options, noReportCommit
			}
			staged, commit := StageDecodeReports(diagnostic.options)
			diagnostic.options = staged
			return []DecodeOption{diagnostic}, commit
		}
	}
	needsStaging := false
	for _, option := range options {
		if tolerance, ok := option.(*toleranceOption); ok && tolerance != nil && tolerance.violations != nil {
			needsStaging = true
			break
		}
	}
	if !needsStaging {
		// Nothing to stage, but the caller still gets an independent copy, as
		// the staged path below returns: later edits to options must not
		// change the paths, limits or replay policy of this call.
		return append([]DecodeOption(nil), options...), noReportCommit
	}
	staged := append([]DecodeOption(nil), options...)
	var commits []func(bool)
	for i, option := range staged {
		tolerance, ok := option.(*toleranceOption)
		if !ok || tolerance == nil || tolerance.violations == nil {
			continue
		}
		destination := tolerance.violations
		scope := destination.scope
		if scope == nil {
			scope = new(reportScope)
		}
		pending := ViolationLog{scope: scope}
		staged[i] = &toleranceOption{violations: &pending, scope: scope}
		commits = append(commits, func(success bool) {
			if success {
				destination.appendBatch(pending.Snapshot())
			}
		})
	}
	var once sync.Once
	return staged, func(success bool) {
		once.Do(func() {
			for _, commit := range commits {
				commit(success)
			}
		})
	}
}

func decodeToleranceNeedsStaging(options []DecodeOption) bool {
	for _, option := range options {
		if tolerance, ok := option.(*toleranceOption); ok && tolerance != nil && tolerance.violations != nil {
			return true
		}
		if child, ok := option.(diagnosticChildOption); ok && decodeToleranceNeedsStaging(child.options) {
			return true
		}
	}
	return false
}

// StageEncodeReports is the encoder counterpart of StageDecodeReports.
func StageEncodeReports(options []EncodeOption) ([]EncodeOption, func(bool)) {
	needsStaging := false
	replay := false
	for _, option := range options {
		if _, ok := option.(replayModeOption); ok {
			replay = true
		}
		if tolerance, ok := option.(*toleranceOption); ok && tolerance != nil && tolerance.violations != nil {
			needsStaging = true
			break
		}
	}
	if !needsStaging {
		if replay {
			// The runtime owns this option chain during one replay pass. Child
			// encoders extend it with capacity-limited appends, so no copy is
			// needed for each generated component.
			return options, noReportCommit
		}
		// An independent copy, as for StageDecodeReports.
		return append([]EncodeOption(nil), options...), noReportCommit
	}
	staged := append([]EncodeOption(nil), options...)
	var commits []func(bool)
	for i, option := range staged {
		tolerance, ok := option.(*toleranceOption)
		if !ok || tolerance == nil || tolerance.violations == nil {
			continue
		}
		destination := tolerance.violations
		scope := destination.scope
		if scope == nil {
			scope = new(reportScope)
		}
		pending := ViolationLog{scope: scope}
		staged[i] = &toleranceOption{violations: &pending, scope: scope}
		commits = append(commits, func(success bool) {
			if success {
				destination.appendBatch(pending.Snapshot())
			}
		})
	}
	var once sync.Once
	return staged, func(success bool) {
		once.Do(func() {
			for _, commit := range commits {
				commit(success)
			}
		})
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
	config.reportScope = option.scope
	if config.reportScope == nil {
		config.reportScope = new(reportScope)
	}
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
	config.reportScope = option.scope
	if config.reportScope == nil {
		config.reportScope = new(reportScope)
	}
	return nil
}

func encodeOptions(options []EncodeOption) (encodeConfig, error) {
	if len(options) == 0 {
		return encodeConfig{}, nil
	}
	var config encodeConfig
	for _, option := range options {
		switch value := option.(type) {
		case constraintPathOption:
			if value == "" || strings.Contains(string(value), ".") {
				return config, fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
			}
			config.collectionSizeChecked = false
			config.hasPath = true
		case withoutBERReplayOption:
			config.noReplay = true
		case replayModeOption:
			if value.state == nil {
				return config, fmt.Errorf("%w: invalid BER replay state", ErrInvalidValue)
			}
			if value.baseline || value.comparison && !value.strict || value.collector != nil && !value.strict {
				config.tolerant = true
				if value.sink != nil {
					config.violations = value.sink
				} else if value.collector != nil && !value.baseline {
					config.violations = &value.collector.sink
				} else {
					config.violations = &value.state.sink
				}
			}
		case parentCollectionSizeOption:
			config.collectionSizeChecked = true
		default:
			return encodeOptionsWithCustom(options)
		}
	}
	return config, nil
}

func encodeOptionsWithCustom(options []EncodeOption) (encodeConfig, error) {
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
	violation.Path = qualifyConstraintPath(options, violation.Path)
	violation.scope = config.reportScope
	if !config.tolerant {
		return &ConstraintError{violation}
	}
	return config.violations.append(violation, config.diagnostics)
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
	violation.Path = qualifyConstraintPath(options, violation.Path)
	violation.scope = config.reportScope
	if config.tolerant {
		return config.violations.append(violation, DiagnosticLimits{})
	}
	return &ConstraintError{violation}
}

type constraintPathOption string

// Paths are already retained as ordered option components. Resolve them only
// when a violation needs an error or report; successful decodes and encodes
// still validate every component without allocating joined prefix strings.
func qualifyConstraintPath[Option any](options []Option, leaf string) string {
	var components []string
	for _, option := range options {
		if diagnostic, ok := any(option).(diagnosticChildOption); ok {
			path := qualifyConstraintPath(diagnostic.options, "")
			if path != "" {
				components = append(components, strings.Split(path, ".")...)
			}
			if diagnostic.isElement {
				components = append(components, fmt.Sprintf("element[%d]", diagnostic.element))
			} else if diagnostic.component != "" {
				components = append(components, diagnostic.component)
			}
			continue
		}
		if context, ok := any(option).(*generatedDecodeOption); ok && context != nil {
			var reverse []string
			for current := context; current != nil; current = current.parent {
				if current.isElement {
					reverse = append(reverse, fmt.Sprintf("element[%d]", current.element))
				} else if current.component != "" {
					reverse = append(reverse, current.component)
				}
			}
			for index := len(reverse); index > 0; index-- {
				components = append(components, reverse[index-1])
			}
			continue
		}
		if component, ok := any(option).(constraintPathOption); ok {
			components = append(components, string(component))
		}
	}
	if len(components) == 0 {
		return leaf
	}
	if leaf != "" {
		components = append(components, leaf)
	}
	return strings.Join(components, ".")
}

func (option constraintPathOption) applyDecode(config *decodeConfig) error {
	config.collectionSizeChecked = false
	if strings.Contains(string(option), ".") || option == "" {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	config.hasPath = true
	return nil
}

func (option constraintPathOption) applyEncode(config *encodeConfig) error {
	config.collectionSizeChecked = false
	if strings.Contains(string(option), ".") || option == "" {
		return fmt.Errorf("%w: invalid BER constraint path component", ErrInvalidValue)
	}
	config.hasPath = true
	return nil
}

// ChildDecodeOptions qualifies violations reported by a nested BER decoder.
func ChildDecodeOptions(options []DecodeOption, component string) []DecodeOption {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			child := &generatedDecodeOption{source: context.source, config: context.config, parent: context, component: component}
			child.config.collectionSizeChecked = false
			child.config.hasPath = true
			return []DecodeOption{child}
		}
	}
	return append(options[:len(options):len(options)], constraintPathOption(component))
}

// ChildEncodeOptions qualifies violations reported by a nested BER encoder.
func ChildEncodeOptions(options []EncodeOption, component string) []EncodeOption {
	for _, option := range options {
		if mode, ok := option.(replayModeOption); ok && (mode.baseline || mode.comparison && mode.strict && !mode.diagnostic || mode.fast != nil && mode.strict && !mode.diagnostic || mode.collector != nil && mode.strict && !mode.diagnostic) {
			return options
		}
	}
	return append(options[:len(options):len(options)], constraintPathOption(component))
}

// ConstraintToleranceEnabled reports whether a validated decode option set
// requested constraint tolerance.
func ConstraintToleranceEnabled(options []DecodeOption) bool {
	config, err := decodeOptions(options)
	return err == nil && config.tolerant
}

type berFormState struct {
	preserve     bool
	validated    *validatedBERSource
	owned        []byte
	proofNeeded  bool
	lightInput   []byte
	lightOwned   []byte
	lightReplay  *ReplayState
	lastCaptured *ReplayNode
}

type berFormOption struct{ state *berFormState }

func (option berFormOption) applyDecode(config *decodeConfig) error {
	config.form = option.state
	return nil
}

// TrackBERForm shares one form marker across a generated value and its children.
// X.690 (02/2021) §§8.1.3, 8.7.3 and 10.2 allow BER forms that DER forbids.
func TrackBERForm(options []DecodeOption) []DecodeOption {
	for _, option := range options {
		if diagnostic, ok := option.(diagnosticChildOption); ok {
			if generatedDecodeHasForm(diagnostic.options) {
				return options
			}
			diagnostic.options = TrackBERForm(diagnostic.options)
			return []DecodeOption{diagnostic}
		}
		if _, ok := option.(*generatedDecodeOption); ok {
			return options
		}
		if _, ok := option.(berFormOption); ok {
			return options
		}
	}
	tracked := append([]DecodeOption(nil), options...)
	return append(tracked, berFormOption{state: new(berFormState)})
}

func generatedDecodeHasForm(options []DecodeOption) bool {
	for _, option := range options {
		switch value := option.(type) {
		case diagnosticChildOption:
			if generatedDecodeHasForm(value.options) {
				return true
			}
		case *generatedDecodeOption, berFormOption:
			return true
		}
	}
	return false
}

// MarkBERNonCanonical records a valid BER form that a schema-aware decoder
// knows the canonical encoder will change, such as an implicit constructed string.
func MarkBERNonCanonical(options []DecodeOption) {
	for _, option := range options {
		if diagnostic, ok := option.(diagnosticChildOption); ok {
			MarkBERNonCanonical(diagnostic.options)
			return
		}
		if context, ok := option.(*generatedDecodeOption); ok && context != nil && context.config.form != nil {
			context.config.form.preserve = true
			return
		}
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
		if diagnostic, ok := option.(diagnosticChildOption); ok {
			return BERNeedsPreservation(diagnostic.options)
		}
		if context, ok := option.(*generatedDecodeOption); ok && context != nil && context.config.form != nil {
			return context.config.form.preserve
		}
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
	if schemaPosition == nil {
		return ErrInvalidValue
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

// PreserveEncodedBER returns the original BER when replay is enabled and the
// current typed value still encodes to its decode-time snapshot. X.690
// (02/2021) §§8.1.3, 8.7.3 permit multiple length forms and constructed string
// segmentations.
func PreserveEncodedBER(encoded, original, snapshot []byte, options []EncodeOption) []byte {
	if BERReplayEnabled(options) && original != nil && bytes.Equal(encoded, snapshot) {
		return append([]byte(nil), original...)
	}
	return encoded
}

// A component checks its complete inherited and local SIZE constraints. The
// child collection omits only its own outer SIZE checks, retaining all element
// validation. X.680 (02/2021) §§51.5.3–51.5.4, 51.8.4.
// A new Child*Options path resets this flag so nested elements check their SIZE.
type parentCollectionSizeOption struct{}

func (parentCollectionSizeOption) applyDecode(config *decodeConfig) error {
	config.collectionSizeChecked = true
	return nil
}
func (parentCollectionSizeOption) applyEncode(config *encodeConfig) error {
	config.collectionSizeChecked = true
	return nil
}

// ParentCollectionSizeDecodeOptions marks a child whose parent checks its SIZE.
func ParentCollectionSizeDecodeOptions(options []DecodeOption) []DecodeOption {
	if len(options) == 1 {
		if context, ok := options[0].(*generatedDecodeOption); ok && context != nil {
			child := *context
			child.config.collectionSizeChecked = true
			return []DecodeOption{&child}
		}
	}
	return append(append([]DecodeOption(nil), options...), parentCollectionSizeOption{})
}

// ParentCollectionSizeEncodeOptions marks a child whose parent checks its SIZE.
func ParentCollectionSizeEncodeOptions(options []EncodeOption) []EncodeOption {
	return append(append([]EncodeOption(nil), options...), parentCollectionSizeOption{})
}

// CheckDecodedCollectionLength reports a standalone assignment name only at
// the root. Nested collections use the existing ASN.1 component/element path.
func CheckDecodedCollectionLength(options []DecodeOption, assignment, constraint string, observed int) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	if config.collectionSizeChecked {
		return nil
	}
	if config.hasPath {
		assignment = ""
	}
	return CheckDecodedLength(options, assignment, constraint, observed)
}

// CheckEncodedCollectionLength is the encoder counterpart.
func CheckEncodedCollectionLength(options []EncodeOption, assignment, constraint string, observed int) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if config.collectionSizeChecked {
		return nil
	}
	if config.hasPath {
		assignment = ""
	}
	return CheckEncodedLength(options, assignment, constraint, observed)
}
