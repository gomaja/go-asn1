package per

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// ToleranceKind names a non-conformant bit run accepted by a tolerant decode.
type ToleranceKind uint8

const (
	// ToleratedTrailingBits is a suffix of more than seven bits after a
	// complete top-level value, or after a complete value carried in an
	// OCTET STRING (CONTAINING ...). X.691 (02/2021) 11.1.3.1 permits only
	// one to seven zero padding bits there; TS 25.331 V19.0.1 12.1.3 and
	// TS 36.331 V19.4.0 8.1 require RRC receivers to accept extraneous bits.
	ToleratedTrailingBits ToleranceKind = iota + 1
	// ToleratedContainedBits is any run of zero or non-zero bits after a
	// complete value carried in a BIT STRING (CONTAINING ...). X.691 (02/2021)
	// 11.1.3.2 forbids them; TS 36.331 V19.4.0 8.1 requires RRC decoders to
	// accept them.
	ToleratedContainedBits
)

func (kind ToleranceKind) String() string {
	switch kind {
	case ToleratedTrailingBits:
		return "trailing bits"
	case ToleratedContainedBits:
		return "contained bits"
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
	// ToleratedContainedBits.
	Offset int
	// Bits holds the accepted bits, MSB first.
	Bits TrailingBits
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
// for tolerance or deferral, so a strict eager decode pays one nil check per
// tracked component.
type decodeTrace struct {
	path    []pathSegment
	pending []Tolerance
	// deferred holds the deferral records of the decode, published to
	// deferrals together with pending.
	deferred  []pendingDeferral
	deferrals *DeferralLog
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

func (bb *BitBuffer) recordTolerance(kind ToleranceKind, offset int, bits TrailingBits) {
	bits.Bytes = append([]byte(nil), bits.Bytes...)
	bb.trace.pending = append(bb.trace.pending, Tolerance{Path: bb.trace.relativePath(), Kind: kind, Offset: offset, Bits: bits})
}

// commitRecords qualifies the pending tolerance and deferral records with
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
		}
		bb.tolerance.append(trace.pending)
		trace.pending = nil
	}
	if len(trace.deferred) != 0 {
		records := make([]Deferral, len(trace.deferred))
		for i, pending := range trace.deferred {
			records[i] = pending.record
			records[i].Path = qualifyPath(root, pending.record.Path)
			// The error is shared with the deferred value, which the
			// caller has not seen yet: it gets the same full path.
			if pending.err != nil {
				pending.err.Path = records[i].Path
			}
		}
		trace.deferrals.append(records)
		trace.deferred = nil
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

// CaptureContainedBits consumes the bits left after a value decoded from a
// BIT STRING (CONTAINING ...). X.691 (02/2021) 11.1.3.2 allows none, so a
// strict decode rejects them. With TrailingBitsTolerance, any number of zero
// or non-zero bits is accepted, as TS 36.331 V19.4.0 8.1 requires of RRC
// decoders, recorded, and returned for re-encoding by AppendContainedBits.
// A value that consumed no bits must be followed by the single zero bit that
// 11.1.3.2 mandates for an empty encoding; that bit is part of the encoding.
func CaptureContainedBits(bb *BitBuffer) (FinalPadding, error) {
	valueBits := bb.bitPos
	if valueBits == 0 {
		if bb.BitsRemaining() == 0 {
			return FinalPadding{}, fmt.Errorf("%w: contained zero-bit value lacks its single zero bit", ErrInvalidValue)
		}
		bit, err := bb.ReadBit()
		if err != nil {
			return FinalPadding{}, err
		}
		if bit != 0 {
			return FinalPadding{}, fmt.Errorf("%w: contained zero-bit complete encoding is nonzero", ErrInvalidValue)
		}
	}
	remaining := bb.BitsRemaining()
	if remaining == 0 {
		return FinalPadding{}, nil
	}
	if bb.tolerance == nil {
		return FinalPadding{}, fmt.Errorf("%w: contained value has %d trailing bits", ErrExtraData, remaining)
	}
	offset := bb.bitPos
	extraBits, err := bb.ReadBitsToBytes(remaining)
	if err != nil {
		return FinalPadding{}, err
	}
	extra := TrailingBits{Bytes: extraBits, BitLength: remaining}
	kept, err := keepTrailing(bb, valueBits, extra)
	if err != nil {
		return FinalPadding{}, err
	}
	bb.recordTolerance(ToleratedContainedBits, offset, extra)
	return kept, nil
}

// AppendContainedBits completes a UPER encoding carried in a BIT STRING
// (CONTAINING ...): it writes the single zero bit of an empty value (X.691
// (02/2021) 11.1.3.2), then reproduces the bits CaptureContainedBits kept.
// The kept bits belong to the received encoding, so they are reproduced only
// after that same encoding. An edited value gets no bits after it, as
// 11.1.3.2 specifies.
func AppendContainedBits(bb *BitBuffer, kept FinalPadding) error {
	if kept.bits != nil && kept.bits.padding.count != 0 {
		return fmt.Errorf("%w: contained bits carry octet padding", ErrInvalidValue)
	}
	unchanged := kept.bits != nil && kept.bits.trailing.BitLength != 0 && kept.bits.follows(bb)
	if bb.bitPos == 0 {
		if err := bb.WriteBit(0); err != nil {
			return err
		}
	}
	if !unchanged {
		return nil
	}
	return bb.WriteBitsFromBytes(kept.bits.trailing.Bytes, kept.bits.trailing.BitLength)
}

// CaptureFinalBits consumes the bits after a complete top-level value and
// publishes the decode's tolerance records, qualified by root, to the
// caller's log. Without TrailingBitsTolerance only the one to seven terminal
// padding bits of X.691 (02/2021) 11.1.3.1 are accepted. With it, a longer
// suffix of zero or non-zero bits is accepted as TS 25.331 V19.0.1 12.1.3
// and TS 36.331 V19.4.0 8.1 require of RRC receivers, and recorded.
//
// A value that consumed no bits is completed by one zero octet (X.691
// (02/2021) 11.1.3.1 and 11.1.4). That octet is part of the complete
// encoding, never a tolerated suffix, and must be zero in either mode.
//
// The decode's deferral records are published with its tolerance records.
// A decode whose ContainedDecoding is unknown, or defers without a
// Deferrals log, fails here, before anything is published.
func CaptureFinalBits(bb *BitBuffer, root string) (FinalPadding, error) {
	if err := bb.checkContainedDecoding(); err != nil {
		return FinalPadding{}, err
	}
	final, err := captureFinalBits(bb, "top-level value")
	if err != nil {
		return FinalPadding{}, err
	}
	bb.commitRecords(root)
	return final, nil
}

// CaptureContainedFinalBits consumes the bits after a value decoded from an
// OCTET STRING (CONTAINING ...), whose contents are a complete encoding with
// the final bits of CaptureFinalBits. bb must have inherited the options of
// the enclosing decode. A suffix accepted under TrailingBitsTolerance, as
// TS 36.331 V19.4.0 8.1 requires of RRC receivers, is recorded in the shared
// trace and published by the enclosing top-level decode.
func CaptureContainedFinalBits(bb *BitBuffer) (FinalPadding, error) {
	return captureFinalBits(bb, "contained value")
}

func captureFinalBits(bb *BitBuffer, context string) (FinalPadding, error) {
	var final FinalPadding
	remaining := bb.BitsRemaining()
	if bb.tolerance == nil || remaining <= 7 || bb.bitPos == 0 && remaining == 8 {
		padding, err := captureTrailingPadding(bb, context)
		if err != nil {
			return FinalPadding{}, err
		}
		final = finalPaddingOf(padding)
	} else {
		valueBits := bb.bitPos
		if valueBits == 0 {
			mandated, err := bb.ReadBits(8)
			if err != nil {
				return FinalPadding{}, err
			}
			if mandated != 0 {
				return FinalPadding{}, fmt.Errorf("%w: %s zero-bit complete encoding is nonzero", ErrInvalidValue, context)
			}
		}
		offset, remaining := bb.bitPos, bb.BitsRemaining()
		suffix, err := bb.ReadBitsToBytes(remaining)
		if err != nil {
			return FinalPadding{}, err
		}
		trailing := TrailingBits{Bytes: suffix, BitLength: remaining}
		if final, err = keepTrailing(bb, valueBits, trailing); err != nil {
			return FinalPadding{}, err
		}
		bb.recordTolerance(ToleratedTrailingBits, offset, trailing)
	}
	return final, nil
}

// FinalPadding retains the bits observed after a complete top-level value:
// the terminal padding of X.691 (02/2021) 11.1.3.1 and 11.1.4, which a sender
// may have set nonzero, or a longer suffix accepted by TrailingBitsTolerance.
// The zero value means no bits other than zero padding were observed. It is
// one pointer wide: every padding value shares a static table, and only a
// tolerated suffix allocates.
//
// Encoding reproduces the retained bits only where they still belong to the
// new encoding; otherwise it emits the padding a new value gets. A suffix is
// replayed only after the value encoding it followed, bit for bit: an edited
// value never carries it. Padding is applied while it still fills the final
// octet exactly (see CompleteBytesWithPadding).
//
// The FinalPadding of a contained value that a decode kept raw holds that
// raw encoding instead (see Deferred).
//
// A decoded SEQUENCE or SET also records here which DEFAULT components of a
// simple type it carried explicitly with their default values (see
// ExplicitDefaults). A record of only the first eight such components of a
// type comes from a shared table and allocates nothing; one that includes a
// later component allocates once. A value kept raw was not decoded, so it
// has no such record.
type FinalPadding struct{ bits *finalBits }

type finalBits struct {
	padding  CompletePadding
	trailing TrailingBits
	// value holds the value encoding that trailing followed, MSB first with
	// unused low bits zero, and valueBits its bit length, not counting the
	// zero octet or bit of an empty value.
	value     []byte
	valueBits int
	// deferred is set only on the shell of a contained value kept raw.
	deferred *Deferred
	// explicitDefaults has bit i set when the decoded value carried its i-th
	// DEFAULT component of a simple type explicitly, holding the default.
	explicitDefaults uint64
}

// keepTrailing retains bits accepted after the value encoding in the first
// valueBits bits of bb, together with a copy of that encoding. Only a
// tolerant decode gets here, so a strict decode never pays for the copy.
func keepTrailing(bb *BitBuffer, valueBits int, trailing TrailingBits) (FinalPadding, error) {
	reader := *bb
	reader.bitPos = 0
	value, err := reader.ReadBitsToBytes(valueBits)
	if err != nil {
		return FinalPadding{}, err
	}
	return FinalPadding{bits: &finalBits{trailing: trailing, value: value, valueBits: valueBits}}, nil
}

// follows reports whether bb holds exactly the value encoding that the
// retained bits followed.
func (kept *finalBits) follows(bb *BitBuffer) bool {
	return bb.bitPos == kept.valueBits && len(bb.data) >= len(kept.value) && bytes.Equal(bb.data[:len(kept.value)], kept.value)
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

// Bits returns the observed terminal padding right-aligned and its width.
// It is zero when a tolerated suffix replaced the padding.
func (f FinalPadding) Bits() (value, count uint8) { return f.Padding().Bits() }

// Padding returns the observed terminal padding.
func (f FinalPadding) Padding() CompletePadding {
	if f.bits == nil {
		return CompletePadding{}
	}
	return f.bits.padding
}

// Trailing returns a copy of the suffix accepted by TrailingBitsTolerance.
// Its BitLength is zero when none was accepted.
func (f FinalPadding) Trailing() TrailingBits {
	if f.bits == nil || f.bits.trailing.BitLength == 0 {
		return TrailingBits{}
	}
	return TrailingBits{Bytes: append([]byte(nil), f.bits.trailing.Bytes...), BitLength: f.bits.trailing.BitLength}
}

// IsZero reports whether every retained bit, padding or suffix, is zero.
func (f FinalPadding) IsZero() bool {
	if f.bits == nil {
		return true
	}
	for _, octet := range f.bits.trailing.Bytes {
		if octet != 0 {
			return false
		}
	}
	return f.bits.padding.IsZero()
}

// CompleteBytesWithFinalPadding returns a complete encoding that reproduces
// the observed final bits while they still fit it. A newly constructed value
// has none, so it encodes with zero padding, as does an edited value whose
// observed bits no longer fit (see FinalPadding).
func (bb *BitBuffer) CompleteBytesWithFinalPadding(final FinalPadding) ([]byte, error) {
	if final.bits == nil {
		return bb.CompleteBytes(), nil
	}
	if final.bits.trailing.BitLength != 0 {
		return bb.completeBytesWithTrailing(final.bits)
	}
	return bb.CompleteBytesWithPadding(final.bits.padding)
}

// CompleteContainedAligned completes an APER encoding carried in a BIT STRING
// (CONTAINING ...). It pads to an octet boundary, or writes the single zero
// octet that X.691 (02/2021) 11.1.4 mandates for an empty encoding, so the
// decoder's complete-encoding check accepts it.
func CompleteContainedAligned(bb *BitBuffer) error {
	if bb.bitPos == 0 {
		return bb.WriteBits(0, 8)
	}
	return bb.AlignToOctetWrite()
}
