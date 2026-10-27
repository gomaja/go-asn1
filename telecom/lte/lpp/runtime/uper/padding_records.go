// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/padding_records.go; SHA-256 c38cc3370abe751acabdd7153c9f7f95927a1b85afcd8c06694dacfcff64d314.
package uper

// PaddingKind identifies the complete encoding whose terminal padding was
// accepted. X.691 (02/2021) §§11.1.3.1, 11.2.1, 19.9 and 23.8 define them.
type PaddingKind uint8

const (
	// FinalEncodingPadding completes a top-level or OCTET STRING-contained value.
	FinalEncodingPadding PaddingKind = iota + 1
	// OpenTypePadding completes an otherwise unclassified open type.
	OpenTypePadding
	// ExtensionAdditionPadding completes a SEQUENCE extension addition or group.
	ExtensionAdditionPadding
	// ChoiceExtensionPadding completes a known CHOICE extension alternative.
	ChoiceExtensionPadding
	// ExtensionGroupPadding completes a multi-component addition group (§19.9).
	ExtensionGroupPadding
)

func (kind PaddingKind) String() string {
	switch kind {
	case FinalEncodingPadding:
		return "final padding"
	case OpenTypePadding:
		return "open type"
	case ExtensionGroupPadding:
		return "extension addition group"
	case ExtensionAdditionPadding:
		return "extension addition"
	case ChoiceExtensionPadding:
		return "choice extension"
	default:
		return "unknown padding"
	}
}

// InputBitSpan locates received bits in the outermost input, MSB first.
// Separate spans omit the length determinants of fragmented open types
// (X.691 (02/2021) §§11.2.2 and 11.9.3.8).
type InputBitSpan struct {
	Offset    int
	BitLength int
}

// paddingRun maps part of a child buffer to the original input. Mappings are
// collected only when InputSpans or PaddingObservations is set; detached inputs have
// no mapping, and a record then leaves InputSpans empty.
type paddingRun struct{ local, input, length int }

type paddingSource struct {
	runs   []paddingRun
	cursor int
}
type paddingTrace struct {
	log     *ToleranceLog
	sources map[*byte]*paddingSource
}

func (bb *BitBuffer) startPaddingObservations(log *ToleranceLog, inputSpans bool) {
	if log == nil && !inputSpans {
		return
	}
	bb.outermost = true
	observations := &paddingTrace{log: log, sources: make(map[*byte]*paddingSource)}

	bb.trace.padding = observations
}

func (bb *BitBuffer) paddingObservations() *paddingTrace {
	if bb.trace == nil {
		return nil
	}
	return bb.trace.padding
}

func (bb *BitBuffer) paddingRuns(start, length int) []paddingRun {
	observations := bb.paddingObservations()
	if observations == nil || len(bb.data) == 0 || start < 0 || length < 0 || start > bb.bitLen || length > bb.bitLen-start {
		return nil
	}
	var result []paddingRun
	if bb.outermost {
		return []paddingRun{{input: start, length: length}}
	}
	source := observations.sources[&bb.data[0]]
	if source == nil || len(source.runs) == 0 {
		return nil
	}
	// Reads normally advance through fragments. Recovery rereads are bounded
	// by the decode work budget; a backwards read rewinds this small cursor.
	for source.cursor > 0 && start < source.runs[source.cursor].local {
		source.cursor--
	}
	for source.cursor < len(source.runs)-1 && source.runs[source.cursor].local+source.runs[source.cursor].length <= start {
		source.cursor++
	}
	for _, run := range source.runs[source.cursor:] {
		if run.local >= start+length {
			break
		}
		// Both endpoints are within the buffer's validated int-sized bit length.
		first, last := max(start, run.local), min(start+length, run.local+run.length)
		if first < last {
			result = append(result, paddingRun{local: first - start, input: run.input + (first - run.local), length: last - first})
		}
	}
	return result
}

func (bb *BitBuffer) rememberPaddingRead(data []byte, start, length int) {
	if bb.paddingObservations() == nil || len(data) == 0 {
		return
	}
	bb.rememberPaddingRuns(data, bb.paddingRuns(start, length))
}

func (bb *BitBuffer) rememberPaddingRuns(data []byte, runs []paddingRun) {
	if observations := bb.paddingObservations(); observations != nil && len(data) != 0 && len(runs) != 0 {
		observations.sources[&data[0]] = &paddingSource{runs: runs}
	}
}

func (bb *BitBuffer) appendPaddingRuns(runs []paddingRun, fragment []byte, offset int) []paddingRun {
	observations := bb.paddingObservations()
	if observations == nil || len(fragment) == 0 {
		return runs
	}
	source := observations.sources[&fragment[0]]
	if source == nil {
		return runs
	}
	for _, run := range source.runs {
		// offset is the length of preceding fragments; the reader bounded the sum.
		run.local += offset
		runs = append(runs, run)
	}
	return runs
}

func (bb *BitBuffer) observePadding(kind PaddingKind, offset int, value uint8, width int) {
	if bb.paddingObservations() == nil || width < 1 || width > 7 || value == 0 {
		return
	}
	if bb.trace.padding.log == nil {
		return
	}
	record := Tolerance{Path: bb.trace.relativePath(), Kind: ToleratedNonzeroPadding, Offset: offset,
		Bits: TrailingBits{Bytes: []byte{value << uint(8-width)}, BitLength: width}, PaddingKind: kind}
	runs := bb.paddingRuns(offset, width)
	covered := 0
	for _, run := range runs {
		if run.local != covered {
			break
		}
		covered += run.length // Disjoint intersections cover at most width (1..7).
	}
	if covered == width {
		for _, run := range runs {
			record.InputSpans = append(record.InputSpans, InputBitSpan{Offset: run.input, BitLength: run.length})
		}
	}
	bb.trace.pending = append(bb.trace.pending, record)
}

// PaddingComponent tracks a field only for explicitly enabled completion
// padding or empty-encoding records.
// Generated decoders use it where no older tolerance needs path tracking.
func (bb *BitBuffer) PaddingComponent(name string) int {
	if bb.trace == nil || (bb.trace.padding == nil || bb.trace.padding.log == nil) && bb.trace.empty == nil {
		return -1
	}
	return bb.trace.enter(pathSegment{name: name})
}

// PaddingIndex tracks a collection element only for those completion records.
func (bb *BitBuffer) PaddingIndex(index int64) int {
	if bb.trace == nil || (bb.trace.padding == nil || bb.trace.padding.log == nil) && bb.trace.empty == nil {
		return -1
	}
	return bb.trace.enter(pathSegment{index: index})
}

// CaptureExtensionPadding completes a known SEQUENCE addition or addition
// group (X.691 (02/2021) §19.9), recording its source-shaped extension path.
func CaptureExtensionPadding(bb *BitBuffer, index int64, group bool) (CompletePadding, error) {
	mark := bb.PaddingComponent("ExtData_")
	bb.PaddingIndex(index)
	kind := ExtensionAdditionPadding
	if group {
		kind = ExtensionGroupPadding
	}
	padding, err := captureTrailingPaddingKind(bb, "open type", kind)
	bb.LeaveComponent(mark)
	return padding, err
}

// CaptureChoicePadding completes a known CHOICE extension alternative
// (X.691 (02/2021) §23.8), recording the selected alternative's path.
func CaptureChoicePadding(bb *BitBuffer, alternative string) (CompletePadding, error) {
	mark := bb.PaddingComponent(alternative)
	padding, err := captureTrailingPaddingKind(bb, "open type", ChoiceExtensionPadding)
	bb.LeaveComponent(mark)
	return padding, err
}

// inputSpans projects an entire received interval; partial mappings stay unknown.
// Enclosing fragment determinants are excluded by paddingRuns (X.691
// (02/2021) §§11.2.2 and 11.9.3.8).
func (bb *BitBuffer) inputSpans(start, end int) []InputBitSpan {
	if bb.paddingObservations() == nil || start < 0 || end < start || end > bb.bitLen {
		return nil
	}
	length := end - start
	runs := bb.paddingRuns(start, length)
	covered := 0
	for _, run := range runs {
		if run.local != covered {
			return nil
		}
		covered += run.length // Disjoint intersections cover at most length.
	}
	if covered != length {
		return nil
	}
	var spans []InputBitSpan
	for _, run := range runs {
		spans = append(spans, InputBitSpan{Offset: run.input, BitLength: run.length})
	}
	return spans
}
