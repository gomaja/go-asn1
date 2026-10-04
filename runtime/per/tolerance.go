package per

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// ToleranceKind names a non-conformant bit run accepted by a tolerant decode.
type ToleranceKind uint8

const (
	// ToleratedTrailingBits is a suffix of more than seven bits after a
	// complete top-level value. X.691 (02/2021) 11.1.3.1 permits only one to
	// seven zero padding bits there; TS 25.331 V19.0.1 12.1.3 requires RRC
	// receivers to accept any bit string in the extension and padding parts.
	ToleratedTrailingBits ToleranceKind = iota + 1
	// ToleratedContainedPadding is zero bits after a complete value carried in
	// a BIT STRING (CONTAINING ...). X.691 (02/2021) 11.1.3.2 forbids them.
	ToleratedContainedPadding
)

func (kind ToleranceKind) String() string {
	switch kind {
	case ToleratedTrailingBits:
		return "trailing bits"
	case ToleratedContainedPadding:
		return "contained padding"
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
	// complete encoding: the top-level input for ToleratedTrailingBits, the
	// BIT STRING contents for ToleratedContainedPadding.
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
// for tolerance, so a strict decode pays one nil check per tracked component.
type decodeTrace struct {
	path    []pathSegment
	pending []Tolerance
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

// commitTolerances qualifies the pending records with the top-level type
// name and publishes them to the caller's log.
func (bb *BitBuffer) commitTolerances(root string) {
	if bb.trace == nil || len(bb.trace.pending) == 0 {
		return
	}
	for i := range bb.trace.pending {
		record := &bb.trace.pending[i]
		switch {
		case record.Path == "":
			record.Path = root
		case strings.HasPrefix(record.Path, "["):
			record.Path = strings.Join([]string{root, record.Path}, "")
		default:
			record.Path = strings.Join([]string{root, record.Path}, ".")
		}
	}
	bb.decodeOptions.TrailingBitsTolerance.append(bb.trace.pending)
	bb.trace.pending = nil
}

// CaptureContainedPadding consumes the bits left after a value decoded from
// a BIT STRING (CONTAINING ...). X.691 (02/2021) 11.1.3.2 forbids padding
// there, so a strict decode rejects them. With TrailingBitsTolerance, up to
// seven zero bits are accepted, recorded and returned for re-encoding. A
// value that consumed no bits must be followed by the single zero bit that
// 11.1.3.2 mandates for an empty encoding; that bit is not padding.
func CaptureContainedPadding(bb *BitBuffer) (CompletePadding, error) {
	if bb.bitPos == 0 {
		if bb.BitsRemaining() == 0 {
			return CompletePadding{}, fmt.Errorf("%w: contained zero-bit value lacks its single zero bit", ErrInvalidValue)
		}
		bit, err := bb.ReadBit()
		if err != nil {
			return CompletePadding{}, err
		}
		if bit != 0 {
			return CompletePadding{}, fmt.Errorf("%w: contained zero-bit complete encoding is nonzero", ErrInvalidValue)
		}
	}
	remaining := bb.BitsRemaining()
	if remaining == 0 {
		return CompletePadding{}, nil
	}
	if bb.decodeOptions.TrailingBitsTolerance == nil {
		return CompletePadding{}, fmt.Errorf("%w: contained value has %d trailing bits", ErrExtraData, remaining)
	}
	offset := bb.bitPos
	padding, err := captureContainedZeroPadding(bb)
	if err != nil {
		return CompletePadding{}, err
	}
	bb.recordTolerance(ToleratedContainedPadding, offset, TrailingBits{Bytes: make([]byte, 1), BitLength: remaining})
	return padding, nil
}

// CaptureFinalBits consumes the bits after a complete top-level value and
// publishes the decode's tolerance records, qualified by root, to the
// caller's log. Without TrailingBitsTolerance only the one to seven terminal
// padding bits of X.691 (02/2021) 11.1.3.1 are accepted. With it, a longer
// suffix is accepted as TS 25.331 V19.0.1 12.1.3 requires of RRC receivers,
// and recorded.
//
// A value that consumed no bits is completed by one zero octet (X.691
// (02/2021) 11.1.3.1 and 11.1.4). That octet is part of the complete
// encoding, never a tolerated suffix, and must be zero in either mode.
func CaptureFinalBits(bb *BitBuffer, root string) (FinalPadding, error) {
	var final FinalPadding
	remaining := bb.BitsRemaining()
	if bb.decodeOptions.TrailingBitsTolerance == nil || remaining <= 7 || bb.bitPos == 0 && remaining == 8 {
		padding, err := CaptureFinalPadding(bb)
		if err != nil {
			return FinalPadding{}, err
		}
		final = finalPaddingOf(padding)
	} else {
		if bb.bitPos == 0 {
			mandated, err := bb.ReadBits(8)
			if err != nil {
				return FinalPadding{}, err
			}
			if mandated != 0 {
				return FinalPadding{}, fmt.Errorf("%w: top-level value zero-bit complete encoding is nonzero", ErrInvalidValue)
			}
		}
		offset, remaining := bb.bitPos, bb.BitsRemaining()
		bytes, err := bb.ReadBitsToBytes(remaining)
		if err != nil {
			return FinalPadding{}, err
		}
		trailing := TrailingBits{Bytes: bytes, BitLength: remaining}
		final = FinalPadding{bits: &finalBits{trailing: trailing}}
		bb.recordTolerance(ToleratedTrailingBits, offset, trailing)
	}
	bb.commitTolerances(root)
	return final, nil
}

// FinalPadding retains the bits observed after a complete top-level value:
// the terminal padding of X.691 (02/2021) 11.1.3.1 and 11.1.4, which a sender
// may have set nonzero, or a longer suffix accepted by TrailingBitsTolerance.
// The zero value means no bits were observed. It is one pointer wide: every
// padding value shares a static table, and only a tolerated suffix allocates.
type FinalPadding struct{ bits *finalBits }

type finalBits struct {
	padding  CompletePadding
	trailing TrailingBits
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
	if padding.count == 0 || padding.count > 7 {
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
// the observed final bits. A newly constructed value has none, so it encodes
// with zero padding.
func (bb *BitBuffer) CompleteBytesWithFinalPadding(final FinalPadding) ([]byte, error) {
	if final.bits == nil {
		return bb.CompleteBytesWithPadding(CompletePadding{})
	}
	if final.bits.trailing.BitLength != 0 {
		return bb.completeBytesWithTrailing(final.bits.trailing)
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
