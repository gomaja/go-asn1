// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/tolerance.go; SHA-256 80e3f7671b7fa00f1555d072709d8a4e121521e42a38f5a214ff75c830e41cc9.
package aper

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// ToleranceKind names a non-conformant bit run accepted by a tolerant decode.
type ToleranceKind uint8

const (
	// ToleratedTrailingBits and ToleratedContainedBits preserve diagnostic
	// kind identities. LPPa APER entry points refuse trailing-bit tolerance.
	ToleratedTrailingBits ToleranceKind = iota + 1
	ToleratedContainedBits
	// ToleratedTruncatedExtension is an extension addition, or extension
	// addition group, of a SEQUENCE or SET whose open type the end of the
	// outermost input cut short, after the extension bitmap was read in full.
	// X.691 (02/2021) 19.9 encodes each present addition as an open type,
	// whose length determinant gives the length of its contents (11.2.1,
	// 11.9.3.8), so a shorter input is an error. TruncatedExtensionTolerance
	// accepts it (go-asn1#114), for receivers of PDUs cut in transmission.
	ToleratedTruncatedExtension
	// ToleratedIncompleteExtension is a known SEQUENCE or SET addition whose
	// complete, bounded open type ended before the known value could decode.
	// X.691 (02/2021) 11.2.1–11.2.2 and 19.9 require a complete encoding;
	// ExtensionRecoveryTolerance explicitly accepts this error (go-asn1#142).
	ToleratedIncompleteExtension
)

func (kind ToleranceKind) String() string {
	switch kind {
	case ToleratedTrailingBits:
		return "trailing bits"
	case ToleratedContainedBits:
		return "contained bits"
	case ToleratedTruncatedExtension:
		return "truncated extension"
	case ToleratedIncompleteExtension:
		return "incomplete extension"
	default:
		return "ToleranceKind(" + strconv.Itoa(int(kind)) + ")"
	}
}

// Tolerance records one bit run that a tolerant decode accepted.
type Tolerance struct {
	// Path is the generated field path in the form used by
	// runtime.DecodePathError, starting with the top-level type name.
	Path string
	Kind ToleranceKind
	// Offset is the position of the first accepted bit within the enclosing
	// complete encoding: the top-level input or the OCTET STRING contents for
	// ToleratedTrailingBits, the BIT STRING contents for
	// ToleratedContainedBits, and the top-level input for
	// ToleratedTruncatedExtension, where it is the first bit of the cut
	// addition's open type: its length determinant, or in the ALIGNED variant
	// the padding before it.
	Offset int
	// Bits holds the accepted bits, MSB first. For ToleratedTruncatedExtension
	// they are the received part of the cut open type, from Offset to the end
	// of the input.
	Bits TrailingBits
	// Missing is, for ToleratedTruncatedExtension, the number of bits that
	// the cut open type lacks: the length its length determinant declares
	// minus the bits that arrived. It is -1 when the input ends inside a
	// length determinant, whose declared length is then unknown. For a
	// fragmented open type (X.691 (02/2021) 11.9.3.8) it counts the missing
	// bits of the fragment that was cut; fragments after it are unknown. It
	// is zero for the other kinds.
	Missing int
	// DeclaredLength is the bounded open type's length in octets for
	// ToleratedIncompleteExtension. Bits keeps those contents as provenance.
	DeclaredLength int
	// ConsumedBits is the position in those contents where decoding failed.
	ConsumedBits int
	// Err is the nested truncation error, qualified by Path on publication.
	// The other tolerance kinds leave these three fields zero.
	Err error
}

// ToleranceLog collects the tolerances applied by PER decodes. A zero value
// is ready for use, and one log may be shared by concurrent decoders. Each
// successful top-level decode appends its records together, in decode order;
// a failed decode appends nothing.
type ToleranceLog struct {
	mu      sync.Mutex
	records []Tolerance
}

// Snapshot returns the records collected so far without exposing the log's
// storage.
func (log *ToleranceLog) Snapshot() []Tolerance {
	log.mu.Lock()
	defer log.mu.Unlock()
	snapshot := make([]Tolerance, len(log.records))
	for i, record := range log.records {
		record.Bits.Bytes = append([]byte(nil), record.Bits.Bytes...)
		snapshot[i] = record
	}
	return snapshot
}

// Reset discards all records collected so far.
func (log *ToleranceLog) Reset() {
	log.mu.Lock()
	log.records = nil
	log.mu.Unlock()
}

func (log *ToleranceLog) append(records []Tolerance) {
	log.mu.Lock()
	log.records = append(log.records, records...)
	log.mu.Unlock()
}

// decodeTrace is the per-decode state shared by a top-level BitBuffer and the
// nested buffers that inherit its options. It exists only when a caller asked
// for extension tolerance, so a strict eager decode pays one nil check per
// tracked component.
type decodeTrace struct {
	path    []pathSegment
	pending []Tolerance
	// truncated is decodeSettings.TruncatedExtensionTolerance (see
	// BitBuffer.outermost).
	truncated *ToleranceLog
	// recovery receives failures of bounded known extension additions.
	recovery *ToleranceLog
	// The recovery work budget belongs to this decode, never to a candidate
	// transaction. Re-reads and provenance scans keep their charges on rollback.
	work *recoveryWork
}

// pathSegment is a component name, or a list index when name is empty.
type pathSegment struct {
	name  string
	index int64
}

func (trace *decodeTrace) enter(segment pathSegment) int {
	trace.path = append(trace.path, segment)
	return len(trace.path) - 1
}

func (trace *decodeTrace) relativePath() string {
	var path strings.Builder
	for _, segment := range trace.path {
		if segment.name == "" {
			path.WriteByte('[')
			path.WriteString(strconv.FormatInt(segment.index, 10))
			path.WriteByte(']')
			continue
		}
		if path.Len() != 0 {
			path.WriteByte('.')
		}
		path.WriteString(segment.name)
	}
	return path.String()
}

// EnterComponent marks the start of a component decode that can apply a
// tolerance. Pass the returned mark to LeaveComponent.
func (bb *BitBuffer) EnterComponent(name string) int {
	if bb.trace == nil {
		return 0
	}
	return bb.trace.enter(pathSegment{name: name})
}

// EnterIndex marks the start of a list element decode that can apply a
// tolerance. Pass the returned mark to LeaveComponent.
func (bb *BitBuffer) EnterIndex(index int64) int {
	if bb.trace == nil {
		return 0
	}
	return bb.trace.enter(pathSegment{index: index})
}

// LeaveComponent restores the path recorded before the matching Enter call.
func (bb *BitBuffer) LeaveComponent(mark int) {
	if bb.trace != nil && mark >= 0 && mark <= len(bb.trace.path) {
		bb.trace.path = bb.trace.path[:mark]
	}
}

// commitRecords qualifies pending extension tolerance records with
// the top-level type name and publishes them to the caller's logs.
func (bb *BitBuffer) commitRecords(root string) {
	trace := bb.trace
	if trace == nil {
		return
	}
	if len(trace.pending) != 0 {
		for i := range trace.pending {
			record := &trace.pending[i]
			record.Path = qualifyPath(root, record.Path)
			if record.Err != nil {
				record.Err = fmt.Errorf("%s: %w", record.Path, record.Err)
			}
		}
		bb.publishTolerances(trace.pending)
		trace.pending = nil
	}
}

// publishTolerances appends records to the log of the option that accepted
// each: TruncatedExtensionTolerance or ExtensionRecoveryTolerance.
// Records for one log are appended
// together, in decode order.
func (bb *BitBuffer) publishTolerances(records []Tolerance) {
	byLog := make(map[*ToleranceLog][]Tolerance)
	for _, record := range records {
		var log *ToleranceLog
		switch record.Kind {
		case ToleratedTruncatedExtension:
			log = bb.trace.truncated
		case ToleratedIncompleteExtension:
			log = bb.trace.recovery
		}
		if log != nil {
			byLog[log] = append(byLog[log], record)
		}
	}
	for log, pending := range byLog {
		log.append(pending)
	}
}

// qualifyPath prefixes a path relative to the top-level value with root, in
// the form of runtime.DecodePathError.
func qualifyPath(root, path string) string {
	switch {
	case path == "":
		return root
	case strings.HasPrefix(path, "["):
		return strings.Join([]string{root, path}, "")
	default:
		return strings.Join([]string{root, path}, ".")
	}
}

// CaptureFinalBits validates and consumes zero terminal padding, returning
// zero padding state, and publishes extension-tolerance records with the
// top-level path (X.691 (02/2021) §11.1.4).
func CaptureFinalBits(bb *BitBuffer, root string) (FinalPadding, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return FinalPadding{}, err
	}
	padding, err := captureTrailingPadding(bb, "top-level value")
	if err != nil {
		return FinalPadding{}, err
	}
	final := finalPaddingOf(padding)
	bb.commitRecords(root)
	return final, nil
}

// FinalPadding carries complete-value padding state and extension provenance.
// Successful APER decoding leaves the padding state zero (X.691 (02/2021)
// §11.1.4). Only package-internal callers can supply non-zero padding state;
// its stored bits are replayed while they still fill the final octet exactly.
type FinalPadding struct{ bits *finalBits }

type finalBits struct {
	padding CompletePadding
	// truncated is set on a decoded SEQUENCE or SET whose extension addition
	// TruncatedExtensionTolerance accepted cut by the end of the input.
	truncated *truncatedExtension
}

// paddingTable holds every CompletePadding with one to seven bits. The entry
// for count bits with value v is at paddingTableOffset[count] + v, and
// paddingTableOffset[count] = 2^count - 1 is also the largest such v.
var paddingTable = func() (table [255]finalBits) {
	for count := uint8(1); count <= 7; count++ {
		for value := uint8(0); value <= paddingTableOffset[count]; value++ {
			table[paddingTableOffset[count]+value].padding = CompletePadding{bits: value, count: count}
		}
	}
	return table
}()

var paddingTableOffset = [8]uint8{0, 1, 3, 7, 15, 31, 63, 127}

func finalPaddingOf(padding CompletePadding) FinalPadding {
	if padding.bits == 0 || padding.count > 7 {
		return FinalPadding{}
	}
	first := paddingTableOffset[padding.count]
	if padding.bits > first {
		return FinalPadding{}
	}
	return FinalPadding{bits: &paddingTable[first+padding.bits]}
}

// Bits returns the stored terminal padding right-aligned and its width.
// Successful APER decoding returns (0, 0).
func (f FinalPadding) Bits() (value, count uint8) { return f.Padding().Bits() }

// Padding returns the stored terminal padding, which is zero after APER decoding.
func (f FinalPadding) Padding() CompletePadding {
	if f.bits == nil {
		return CompletePadding{}
	}
	return f.bits.padding
}

// Trailing returns an empty suffix. APER entry points reject trailing-bit
// tolerance; padding and extension provenance never carry such a suffix.
func (f FinalPadding) Trailing() TrailingBits { return TrailingBits{} }

// IsZero reports whether every stored padding bit is zero.
func (f FinalPadding) IsZero() bool { return f.bits == nil || f.bits.padding.IsZero() }

// CompleteBytesWithFinalPadding returns a complete encoding using the stored
// padding state (see CompleteBytesWithPadding). APER decoders leave that state
// zero, so their values encode with zero terminal padding (X.691 (02/2021)
// §11.1.4).
func (bb *BitBuffer) CompleteBytesWithFinalPadding(final FinalPadding) ([]byte, error) {
	if final.bits == nil {
		return bb.CompleteBytes(), nil
	}
	return bb.CompleteBytesWithPadding(final.bits.padding)
}
