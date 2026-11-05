// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_string_contents.go; SHA-256 e409c3832a94e22abfaab1a9dce646d92a74b9f7555f47387db505c09c55616c.
package ber

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// X.680 (02/2021) §41 Tables 8–10 and §51.7: generated MAP
// fields already check the intersection of their repertoire and FROM constraint.
// X.690 (02/2021) §§8.15, 8.23.1, 8.23.4–8.23.8, 8.25 also apply to open values.
// Keep one provisional entry per invalid element until the typed walk claims
// its contents. Neither valid input nor each bad octet needs pending storage.
type deferredStringState struct {
	offsets  []int
	byOffset map[int]*deferredStringContents
}

type deferredStringContents struct {
	data     []byte
	number   int
	position Violation
	typed    bool
}

func validateGeneratedBERElement(data []byte, options []DecodeOption) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	config.generatedContents = true
	config.skipRestrictedContents = true
	return validateBERElement(data, options, config)
}

func deferGeneratedStringContents(data []byte, offset int, stack []berScanFrame, index, number int, config decodeConfig, options []DecodeOption) error {
	if config.form == nil {
		return nil
	} // The preliminary ownership scan checks structure only.
	positionConfig := config
	positionConfig.tolerant = true
	position, err := scannedUTF8Location(data, offset, stack, index, positionConfig, options)
	if err != nil {
		return err
	}
	if config.form.mapPending == nil {
		root := data
		if config.location != nil {
			root = config.location.rootInput()
		}
		config.form.mapPending = &mapProfileState{root: root, byOffset: make(map[int]*mapProfileElement)}
	}
	pending := config.form.mapPending
	absolute := *position.Offset
	if pending.contents == nil {
		pending.contents = &deferredStringState{byOffset: make(map[int]*deferredStringContents)}
	}
	candidates := pending.contents
	if candidates.byOffset[absolute] != nil {
		return nil
	}
	candidates.byOffset[absolute] = &deferredStringContents{data: data[offset:], number: number, position: position}
	// Root scans encounter identifiers in increasing order. Reconstructed or
	// repeated child scans reuse their root entry rather than adding a candidate.
	i := sort.SearchInts(candidates.offsets, absolute)
	candidates.offsets = slices.Insert(candidates.offsets, i, absolute)
	config.form.preserve = true
	return nil
}

func generatedContentsPosition(config decodeConfig, options []DecodeOption) bool {
	return config.form != nil && (config.form.lightInput != nil || config.form.validated != nil) || generatedPreflightProbeActive(options)
}

func claimGeneratedAlphabet(config decodeConfig, options []DecodeOption) {
	if config.form == nil || config.form.mapPending == nil || config.form.mapPending.contents == nil || config.location == nil {
		return
	}
	leaf := config.location.fieldName()
	path := qualifyConstraintPath(options, "")
	if leaf != "" && !config.location.fieldAlreadyApplied(options) {
		path = joinUTF8Path(path, leaf)
	}
	v, err := locateViolation(config, Violation{Path: path}, leaf)
	if err != nil || v.Offset == nil {
		return
	}
	if candidate := config.form.mapPending.contents.byOffset[*v.Offset]; candidate != nil {
		candidate.typed = true
	}
}

func locateGeneratedStringContents(config decodeConfig, location *decodeLocation, raw []byte, name string, length int, options []DecodeOption) {
	if config.form == nil || config.form.mapPending == nil || config.form.mapPending.contents == nil || location == nil || length < 0 || length > len(raw) {
		return
	}
	pending := config.form.mapPending
	start, ok := location.wireOffset(raw)
	if !ok {
		return
	}
	prefix := qualifyConstraintPath(options, name)
	depth := 0
	if prefix != "" {
		depth = len(strings.Split(prefix, "."))
	}
	for _, offset := range pending.contents.offsets[sort.SearchInts(pending.contents.offsets, start):] {
		if offset-start >= length {
			break
		}
		candidate := pending.contents.byOffset[offset]
		if candidate == nil || depth < candidate.position.schemaDepth {
			continue
		}
		base, err := location.decodeOrigin().ancestry(start)
		if err != nil {
			continue
		}
		path := prefix
		for _, child := range candidate.position.ChildIndexes[min(len(base), len(candidate.position.ChildIndexes)):] {
			path = joinUTF8Path(path, fmt.Sprintf("child[%d]", child))
		}
		candidate.position.Path, candidate.position.Source, candidate.position.schemaDepth = path, sourceField(location.source, name), depth
	}
}

func finishGeneratedStringContents(config decodeConfig) error {
	pending := config.form.mapPending
	if pending.contents == nil {
		return nil
	}
	for _, offset := range pending.contents.offsets {
		candidate := pending.contents.byOffset[offset]
		if candidate == nil || candidate.typed {
			continue
		}
		position := candidate.position
		// Decoding the already structurally checked element reassembles segments
		// once, only for a refused or tolerated open string (X.690 §8.23.3).
		budget, err := newBERWorkBudget(nil)
		if err != nil {
			return err
		}
		budget.limits = config.limits
		var contents []byte
		_, _, err = decodeStringSegments(candidate.data, candidate.number, 0, &budget, &contents)
		if err != nil {
			cause := &ElementError{offset: offset, childIndexes: position.ChildIndexes, cause: err}
			if position.Path != "" {
				return &preflightPathError{path: position.Path, cause: cause}
			}
			return cause
		}
		var contentsErr error
		if isAlphabetString(candidate.number) {
			contentsErr = checkAlphabetString(candidate.number, contents, budget.stringSource, 0, config, nil, true, &position)
		} else {
			contentsErr = validateRestrictedStringContents(candidate.number, contents)
		}
		if err := contentsErr; err != nil {
			cause := &ElementError{offset: offset, childIndexes: position.ChildIndexes, cause: err}
			if position.Path != "" {
				return &preflightPathError{path: position.Path, cause: cause}
			}
			return cause
		}
	}
	return nil
}

// Generated typed checks own their repertoire and FROM constraints (X.680
// (02/2021) §41 and §51.7). Only an opaque interval needs the new generic
// contents scan (X.690 (02/2021) §§8.15, 8.23–8.25). Its findings stay deferred
// until the complete typed decode succeeds, preserving prior error precedence.
func checkGeneratedOpaqueContents(config decodeConfig, raw []byte, length int, options []DecodeOption) {
	if !generatedContentsPosition(config, options) || !config.form.hasRestrictedContents() || length < 0 || length > len(raw) {
		return
	}
	config.generatedContents = true
	config.skipRestrictedContents = false
	if err := validateBERElement(raw[:length], options, config); err != nil {
		if config.form.mapPending == nil {
			config.form.mapPending = &mapProfileState{root: raw, byOffset: make(map[int]*mapProfileElement)}
		}
		config.form.mapPending.failure = &mapProfileFailure{err}
	}
}

// A generated tag mismatch can return directly without a runtime rejection
// helper. Recheck only that failure path so malformed contents retain their
// X.690 (02/2021) §§8.1.2, 8.23–8.25 classification. Existing typed alphabet
// reports claim their identifiers, just as the earlier semantic walk did.
func recheckGeneratedRejection(config decodeConfig) error {
	location := config.location
	if location == nil {
		return nil
	}
	claimReportedGeneratedContents(config)
	scan := config
	scan.generatedContents = true
	scan.skipRestrictedContents = false
	scan.location = location.root
	if err := validateBERElement(location.rootInput(), nil, scan); err != nil {
		return err
	}
	pending := config.form.mapPending
	if pending == nil || pending.contents == nil {
		return nil
	}
	for current := location; current != nil; current = current.parent {
		if current.context != nil {
			locateGeneratedStringContents(config, current, current.input, "", len(current.input), []DecodeOption{current.context})
		}
	}
	return finishGeneratedStringContents(config)
}

// Only refused decodes need to reconstruct ownership from their native reports.
// Preclaim before the ordered rescan so already visited typed strings allocate
// no candidate and cannot consume a second diagnostic budget (X.680 (02/2021) §51.7).
func claimReportedGeneratedContents(config decodeConfig) {
	if config.violations == nil {
		return
	}
	records := config.violations
	if config.reportScope != nil {
		config.reportScope.mu.Lock()
		defer config.reportScope.mu.Unlock()
		records = &config.reportScope.ledger
	} else {
		records.mu.Lock()
		defer records.mu.Unlock()
	}
	for _, record := range records.records {
		if record.scope != config.reportScope || record.Offset == nil || record.OctetOffset != nil {
			continue
		}
		if config.form.mapPending == nil {
			config.form.mapPending = &mapProfileState{root: config.location.rootInput(), byOffset: make(map[int]*mapProfileElement)}
		}
		pending := config.form.mapPending
		if pending.contents == nil {
			pending.contents = &deferredStringState{byOffset: make(map[int]*deferredStringContents)}
		}
		if candidate := pending.contents.byOffset[*record.Offset]; candidate != nil {
			candidate.typed = true
		} else {
			pending.contents.byOffset[*record.Offset] = &deferredStringContents{typed: true}
		}
	}
}

// CheckGeneratedUnknownContents checks a preserved extension addition without
// relabelling existing UTF8String reports (X.690 (02/2021) §§8.23–8.25).
func CheckGeneratedUnknownContents(options []DecodeOption, raw []byte, length int) {
	if config, err := decodeOptions(options); err == nil {
		checkGeneratedOpaqueContents(config, raw, length, options)
		if location := config.location; location != nil {
			locateGeneratedStringContents(config, location, location.input, "", len(location.input), options)
		}
	}
}
