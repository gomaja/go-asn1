// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/truncated.go; SHA-256 d88969c4ae65c93fabfa548a88d1c7e99f9c8ef5de443e1b674884e8975aa819.
package uper

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/gomaja/go-asn1/telecom/umts/rrc/runtime"
)

// ExtensionAdditions is the decode state of the extension additions of one
// SEQUENCE or SET value (X.691 (02/2021) 19.7 to 19.9). A generated decoder
// takes it with BeginExtensionAdditions before the value's extension bit,
// reads the extension bitmap through it, and asks Received before it reads
// the open type of each present addition. Without TruncatedExtensionTolerance
// it only keeps bit positions and allocates nothing.
//
// Under TruncatedExtensionTolerance, an addition whose open type the end of
// the outermost input cuts short is not read: Received reports it, and every
// later addition, as not received, clears their bits in the decoded bitmap,
// records the cut, and consumes the rest of the input. Record then keeps
// what an unchanged value needs to re-encode as received.
type ExtensionAdditions struct {
	// start is the position of the extension bit, root that of the bitmap
	// length, bitmap that of the first bitmap bit and end the position after
	// the last one.
	start, root, bitmap, end int
	aligned                  bool
	present                  []bool
	cut                      *truncatedExtension
	recovered                bool
	// open is the position of the open type that Received last admitted.
	open int
}

// BeginExtensionAdditions starts the extension additions of a SEQUENCE or SET
// value whose encoding starts at the read position of bb, with its extension
// bit.
func BeginExtensionAdditions(bb *BitBuffer) ExtensionAdditions {
	return ExtensionAdditions{start: bb.bitPos}
}

// DecodeBitmap reads the extension bitmap that follows the root components
// (X.691 (02/2021) 19.8), as DecodeExtensionBitmap does.
func (a *ExtensionAdditions) DecodeBitmap(bb *BitBuffer) (int64, []bool, error) {
	return a.decodeBitmap(bb, DecodeExtensionBitmap, false)
}

// DecodeBitmapAligned is the APER form of DecodeBitmap.

func (a *ExtensionAdditions) decodeBitmap(bb *BitBuffer, decode func(*BitBuffer) (int64, []bool, error), aligned bool) (int64, []bool, error) {
	a.root, a.aligned = bb.bitPos, false
	count, present, err := decode(bb)
	a.end, a.present = bb.bitPos, present
	if err == nil && len(present) <= a.end {
		a.bitmap = a.end - len(present)
	}
	return count, present, err
}

// Received reports whether the open type of the present extension addition
// index, at the read position of bb, is to be read. It is false once an
// addition was cut by the end of the input. Otherwise it is true, unless
// TruncatedExtensionTolerance is set, bb reads the outermost input, and that
// input ends inside the open type's length determinant or contents: the
// addition is then the cut one. A decode without the option, or of an open
// type nested in another encoding, reads the open type and reports its error.
// An admitted open type's position becomes the Offset of the record that
// CompleteKnownAddition makes if the addition's known value is incomplete.
func (a *ExtensionAdditions) Received(bb *BitBuffer, index int64) bool {
	if a.cut != nil {
		return false
	}
	a.open = bb.bitPos
	if !bb.outermost || bb.trace == nil || bb.trace.truncated == nil {
		return true
	}
	return a.receive(bb, index)
}

// receive is Received under TruncatedExtensionTolerance for the outermost
// input.
func (a *ExtensionAdditions) receive(bb *BitBuffer, index int64) bool {
	if index < 0 || index >= int64(len(a.present)) || bb.invalidLength || bb.bitLen%8 != 0 || bb.bitLen/8 != len(bb.data) {
		return true
	}
	missing, cut := openTypeCut(*bb, a.aligned)
	if !cut {
		return true
	}
	cutAt, offset, received := int(index), bb.bitPos, bb.BitsRemaining()
	kept := false
	for i, present := range a.present {
		kept = kept || i < cutAt && present
	}
	input := append([]byte(nil), bb.data...)
	reader := *bb
	reader.data, reader.bitPos = input, 0
	record, err := a.cutRecord(&reader, input, cutAt, offset, kept)
	if err != nil {
		return true
	}
	tail, err := bb.ReadBitsToBytes(received)
	if err != nil {
		return true
	}
	trace := bb.trace
	mark := trace.enter(pathSegment{name: "ExtData_"})
	trace.enter(pathSegment{index: index})
	trace.pending = append(trace.pending, Tolerance{
		Path:    trace.relativePath(),
		Kind:    ToleratedTruncatedExtension,
		Offset:  offset,
		Bits:    TrailingBits{Bytes: tail, BitLength: received},
		Missing: missing,
	})
	trace.path = trace.path[:mark]
	for i := range a.present {
		if i >= cutAt {
			a.present[i] = false
		}
	}
	a.cut = record
	return false
}

// cutRecord builds the record of a cut at addition cutAt, whose open type
// starts at offset of input, a complete outermost input of bits bits. It
// holds the encoding the decoded value, unchanged, gets from the start of the
// input to its own end: the input up to the cut addition with the bitmap bits
// of the cut and later additions cleared or, when no addition before the cut
// was present, the input up to the end of the value's root with its extension
// bit cleared (X.691 (02/2021) 19.1).
func (a *ExtensionAdditions) cutRecord(reader *BitBuffer, input []byte, cutAt, offset int, kept bool) (*truncatedExtension, error) {
	bits := reader.bitLen
	expected := NewBitBuffer()
	if kept {
		if err := copyBits(expected, reader, a.bitmap); err != nil {
			return nil, err
		}
		for i := range a.present {
			bit, err := reader.ReadBit()
			if err != nil {
				return nil, err
			}
			if i >= cutAt {
				bit = 0
			}
			if err := expected.WriteBit(bit); err != nil {
				return nil, err
			}
		}
		if offset < reader.bitPos {
			return nil, fmt.Errorf("%w: cut addition at bit %d precedes the bitmap end %d", ErrInvalidValue, offset, reader.bitPos)
		}
		if err := copyBits(expected, reader, offset-reader.bitPos); err != nil {
			return nil, err
		}
	} else {
		if err := copyBits(expected, reader, a.start); err != nil {
			return nil, err
		}
		if _, err := reader.ReadBit(); err != nil {
			return nil, err
		}
		if err := expected.WriteBit(0); err != nil {
			return nil, err
		}
		if a.root < reader.bitPos {
			return nil, fmt.Errorf("%w: root end %d precedes the extension bit", ErrInvalidValue, a.root)
		}
		if err := copyBits(expected, reader, a.root-reader.bitPos); err != nil {
			return nil, err
		}
	}
	return &truncatedExtension{input: input, bits: bits, expected: expected.data, expectedBits: expected.bitPos, kept: kept, cut: true}, nil
}

// copyBits appends the next count bits of from to to.
func copyBits(to, from *BitBuffer, count int) error {
	bits, err := from.ReadBitsToBytes(count)
	if err != nil {
		return err
	}
	return to.WriteBitsFromBytes(bits, count)
}

// openTypeCut reports whether the open type at the read position of reader,
// a copy of the decoding buffer, runs past the end of its input: the walk of
// its length determinants and fragments is the one DecodeOpenType and
// DecodeOpenTypeAligned make (X.691 (02/2021) 11.2.1, 11.9.3.8), with the
// contents skipped. missing is the number of bits the cut fragment lacks, or
// -1 when the input ends inside a length determinant. Any other error is left
// for the read itself to report.
func openTypeCut(reader BitBuffer, aligned bool) (missing int, cut bool) {
	missing = -1
	_, err := decodeLengthFragmentsBounded(&reader, false, math.MaxInt64, func(_ int64, length int64) error {
		if length < 0 || length > int64(math.MaxInt/8) {
			return ErrInvalidValue
		}
		bits := int(length) * 8
		if remaining := reader.BitsRemaining(); bits > remaining {
			missing = bits - remaining
			return ErrTruncated
		}
		reader.bitPos += bits
		return nil
	})
	if err == nil || !errors.Is(err, ErrTruncated) {
		return 0, false
	}
	return missing, true
}

// Emptied reports whether a cut left the value with no extension addition:
// the decoder then clears its extension state, as for a value received with
// a zero extension bit, so that an edited value is encoded with none (X.691
// (02/2021) 19.1).
func (a *ExtensionAdditions) Emptied() bool {
	if a.cut != nil && !a.cut.kept {
		return true
	}
	if a.recovered {
		for _, present := range a.present {
			if present {
				return false
			}
		}
		return true
	}
	return false
}

// Record returns final, the decoded value's PERPadding_, together with the
// cut, if an addition was cut. Without a cut it returns final unchanged and
// allocates nothing.
func (a *ExtensionAdditions) Record(final FinalPadding) FinalPadding {
	if a.cut == nil {
		return final
	}
	var merged finalBits
	if final.bits != nil {
		merged = *final.bits
	}
	merged.truncated = a.cut
	return FinalPadding{bits: &merged}
}

// Truncated reports whether the decoded value had an extension addition cut
// by the end of the input (TruncatedExtensionTolerance), so that an
// unchanged value re-encodes to the received input.
func (f FinalPadding) Truncated() bool {
	return f.bits != nil && f.bits.truncated != nil && (!f.bits.truncated.recovered || f.bits.truncated.cut)
}

// truncatedExtension is the record of a SEQUENCE or SET value whose extension
// addition was cut by the end of the input: a copy of the whole input, of
// bits bits, which the unchanged value re-encodes to, and the encoding the
// unchanged value gets up to its own end, of expectedBits bits. kept is set
// when an addition before the cut one was received, so the value keeps its
// extension bit and bitmap.
// For bounded recovery without an outer-input cut, both encodings instead
// hold only the local value's bits, together with its starting alignment.
type truncatedExtension struct {
	input        []byte
	bits         int
	expected     []byte
	expectedBits int
	kept         bool
	cut          bool
	recovered    bool
	// phase is the recovered value's starting position modulo eight.
	// Only bounded recovery uses it; an outer-input cut retains its
	// whole-input comparison for go-asn1#114.
	phase int
}

// AppendTruncatedExtension completes the encoding of a SEQUENCE or SET value
// whose PERPadding_ is final. A value decoded with an extension addition cut
// by the end of the input (TruncatedExtensionTolerance) re-encodes to the
// received input, octet for octet, while its encoding, and everything bb
// holds before it, is the one the unchanged decoded value gets. Any edit
// before the cut changes that encoding, so an edited value keeps the
// encoding just written: a new one, without the cut additions. Every other
// value is left as written, and nothing is allocated.
//
// The received input ends inside the cut addition, so nothing can follow it.
// Whatever an enclosing value could add after it is announced by a bit
// before it, such as a presence bit, extension bit or count, which the
// comparison covers.
func AppendTruncatedExtension(bb *BitBuffer, final FinalPadding) {
	if !final.Truncated() {
		return
	}
	final.bits.truncated.replay(bb)
}

// AppendExtensionRecovery replays bounded-addition recovery for the value
// whose encoder began at start. Comparing its exact span prevents a changed
// length from matching only a suffix of the old typed encoding. APER also
// requires the same starting alignment (X.691 (02/2021) 11.1.4, 11.2.2).
// An outer-input cut is handled separately by AppendTruncatedExtension.
func AppendExtensionRecovery(bb *BitBuffer, final FinalPadding, start int) {
	if !final.Recovered() || final.Truncated() {
		return
	}
	cut := final.bits.truncated
	if start < 0 || start > bb.bitPos {
		return
	}
	if bb.bitPos-start != cut.expectedBits || !cut.follows(bb) {
		return
	}
	cut.replayLocal(bb)
}

func (cut *truncatedExtension) replay(bb *BitBuffer) {
	if !cut.follows(bb) {
		return
	}
	bb.data = append(bb.data[:0], cut.input...)
	bb.bitPos = cut.bits
}

// replayLocal replaces only this value's suffix. Preserve the partial octet
// before it without retaining or copying any preceding complete octets.
func (cut *truncatedExtension) replayLocal(bb *BitBuffer) {
	start := bb.bitPos - cut.expectedBits // AppendExtensionRecovery checked the exact span
	if cut.bits < 0 || cut.bits > math.MaxInt-start {
		return
	}
	leading := start % 8
	var prefix uint64
	if leading != 0 {
		prefix = uint64(bb.data[start/8]) >> uint(8-leading)
	}
	bb.bitPos = start - leading
	bb.data = bb.data[:bb.bitPos/8]
	if err := bb.WriteBits(prefix, leading); err != nil {
		return
	}
	if err := bb.WriteBitsFromBytes(cut.input, cut.bits); err != nil {
		return
	}
}

// follows compares the unchanged value's local encoding and alignment, or
// the whole prefix when an outer-input cut requires it. A write buffer's
// unused low bits are zero, as the expected encoding's are.
func (cut *truncatedExtension) follows(bb *BitBuffer) bool {
	if cut.recovered && !cut.cut {
		if cut.expectedBits < 0 || cut.expectedBits > bb.bitPos {
			return false
		}
		start := bb.bitPos - cut.expectedBits
		if start%8 != cut.phase {
			return false
		}
		// These are typed encodings already held by the caller, not a new
		// receiver input. A one-pass ceiling based on their length preserves
		// replay for values decoded under raised DecodeLimits.MaxWork.
		var readBudget, expectedBudget DecodeBudget
		readBudget.limits = DefaultDecodeLimits()
		readBudget.limits.MaxWork = cut.expectedBits
		reader := *bb
		reader.bitPos, reader.bitLen, reader.budget = start, bb.bitPos, &readBudget
		expected := NewDecodeBuffer(cut.expected, &expectedBudget)
		expectedBudget.limits.MaxWork = cut.expectedBits
		for remaining := cut.expectedBits; remaining > 0; {
			width := min(remaining, 64)
			got, err := reader.ReadBits(width)
			if err != nil {
				return false
			}
			want, err := expected.ReadBits(width)
			if err != nil || got != want {
				return false
			}
			remaining -= width
		}
		return true
	}
	return bb.bitPos == cut.expectedBits && bytes.Equal(bb.data, cut.expected)
}

// KnownAdditionCheckpoint marks pending records before a candidate decode.
// It contains no buffer pointers, so a generated decoder can keep its shared
// budget on the stack even when extension recovery is enabled.
type KnownAdditionCheckpoint struct{ path, pending, deferred int }

// CheckpointKnownAddition records the transaction boundary before decoding a
// fully received known addition. The child must already have entered its
// open-type scope.
func (bb *BitBuffer) CheckpointKnownAddition() KnownAdditionCheckpoint {
	if bb.trace == nil {
		return KnownAdditionCheckpoint{}
	}
	return KnownAdditionCheckpoint{len(bb.trace.path), len(bb.trace.pending), len(bb.trace.deferred)}
}

// CompleteKnownAddition finishes a caller-owned candidate and closes its
// open-type scope. The caller commits typed fields only when decoded is true.
// X.691 (02/2021) §§19.9 and 11.2.1–11.2.2 delimit additions with complete
// open types; only nested truncation is recoverable. Resource limits, padding,
// constraints and unsupported constructs fail. Failed candidates roll back
// pending records, never their resource usage. A recovered addition's
// record locates its open type where Received admitted it.
func (a *ExtensionAdditions) CompleteKnownAddition(child *BitBuffer, index int64, data []byte, checkpoint KnownAdditionCheckpoint, err error, group bool) (decoded bool, padding CompletePadding, result error) {
	defer child.LeaveOpenType()
	trace := child.trace
	if trace != nil {
		defer func() { trace.path = trace.path[:checkpoint.path] }()
	}
	if limitErr := child.checkRecoveryBits(0); limitErr != nil {
		err = limitErr
	}
	if err == nil {
		padding, err = CaptureExtensionPadding(child, index, group)
		if err != nil {
			err = runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", index))
		}
		return err == nil, padding, err
	}
	if trace != nil {
		trace.path = trace.path[:checkpoint.path]
		trace.pending = trace.pending[:checkpoint.pending]
		trace.deferred = trace.deferred[:checkpoint.deferred]
		if trace.work != nil && trace.work.err == nil {
			trace.work.recordRollback(data, child.bitPos)
		}
	}
	if trace == nil || trace.recovery == nil || index < 0 || index >= int64(len(a.present)) || !a.present[index] || child.invalidLength || !onlyTruncated(err) {
		return false, CompletePadding{}, err
	}
	trace.enter(pathSegment{name: "ExtData_"})
	trace.enter(pathSegment{index: index})
	trace.pending = append(trace.pending, Tolerance{
		Path: trace.relativePath(), Kind: ToleratedIncompleteExtension, Offset: a.open,
		Bits:           TrailingBits{Bytes: append([]byte(nil), data...), BitLength: child.bitLen},
		DeclaredLength: len(data), ConsumedBits: child.bitPos, Err: err,
	})
	a.present[index], a.recovered = false, true
	return false, CompletePadding{}, nil
}

// onlyTruncated admits the truncation sentinel through single-error wrappers.
// An error tree containing both truncation and a structural/limit failure is
// never recoverable, even when errors.Is would match ErrTruncated.
func onlyTruncated(err error) bool {
	for err != nil {
		if err == ErrTruncated {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

// Recovered reports a failed bounded known addition in this decode.
func (a *ExtensionAdditions) Recovered() bool { return a.recovered }

// RecoveryEncoder returns an encoder with only the starting bit position
// modulo eight as alignment context (X.691 (02/2021) 11.1.4, 11.2.2). The
// generated decoder encodes the surviving typed fields here; no parent prefix
// is copied. A later outer-input cut retains go-asn1#114's prefix comparison.
func (a *ExtensionAdditions) RecoveryEncoder(bb *BitBuffer) (*BitBuffer, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return nil, err
	}
	if a.start < 0 || a.start > bb.bitPos || bb.bitPos > bb.bitLen {
		return nil, fmt.Errorf("%w: invalid recovery start %d at bit %d", ErrInvalidValue, a.start, bb.bitPos)
	}
	encoded := NewBitBuffer()
	if a.cut == nil {
		if err := encoded.WriteBits(0, a.start%8); err != nil {
			return nil, err
		}
		return encoded, nil
	}
	reader := *bb
	reader.bitPos = 0
	if bb.trace != nil && bb.trace.work != nil {
		active := bb.trace.work.active
		bb.trace.work.active = true
		defer func() { bb.trace.work.active = active }()
	}
	if err := copyBits(encoded, &reader, a.start); err != nil {
		return nil, err
	}
	return encoded, nil
}

// RecordRecovery stores received bytes separately from the typed fields.
// expected is the encoding of those fields, with failed additions absent.
// Both encodings are relative to this value, excluding the parent prefix and
// the temporary alignment context. AppendExtensionRecovery replays only
// while the local typed encoding and starting alignment are unchanged. An
// edit emits the surviving typed fields with failed additions omitted
// (X.691 (02/2021) 19.1, 19.8).
// It also retains a later outer-input cut accepted under go-asn1#114.
func (a *ExtensionAdditions) RecordRecovery(bb, expected *BitBuffer, final FinalPadding) (FinalPadding, error) {
	if err := bb.checkRecoveryBits(0); err != nil {
		return FinalPadding{}, err
	}
	if a.start < 0 || a.start > bb.bitPos || bb.bitPos > bb.bitLen {
		return FinalPadding{}, fmt.Errorf("%w: invalid recovery start %d at bit %d", ErrInvalidValue, a.start, bb.bitPos)
	}
	start, phase := 0, 0
	if a.cut == nil {
		start, phase = a.start, a.start%8
	}
	if expected.bitPos < phase {
		return FinalPadding{}, fmt.Errorf("%w: recovery encoding ends before its alignment context", ErrInvalidValue)
	}
	reader := *bb
	reader.bitPos = start
	inputBits, expectedBits := bb.bitPos-start, expected.bitPos-phase
	if bb.trace != nil && bb.trace.work != nil {
		active := bb.trace.work.active
		bb.trace.work.active = true
		defer func() { bb.trace.work.active = active }()
	}
	input, err := reader.ReadBitsToBytes(inputBits)
	if err != nil {
		return FinalPadding{}, err
	}
	written := *expected
	written.bitPos, written.bitLen = phase, expected.bitPos
	written.trace, written.budget = bb.trace, bb.decodeBudget()
	typed, err := written.ReadBitsToBytes(expectedBits)
	if err != nil {
		return FinalPadding{}, err
	}
	var merged finalBits
	if final.bits != nil {
		merged = *final.bits
	}
	merged.truncated = &truncatedExtension{
		input: input, bits: inputBits, expected: typed, expectedBits: expectedBits,
		cut: a.cut != nil, recovered: true, phase: phase,
	}
	return FinalPadding{bits: &merged}, nil
}

// Recovered reports whether a value keeps bounded-addition recovery provenance.
func (f FinalPadding) Recovered() bool {
	return f.bits != nil && f.bits.truncated != nil && f.bits.truncated.recovered
}

// RecoveryEnabled reports the explicit bounded-addition recovery policy.
func (a *ExtensionAdditions) RecoveryEnabled(bb *BitBuffer) bool {
	return bb.trace != nil && bb.trace.recovery != nil
}

// RecoveryComponent enters a path under bounded-addition recovery or an
// explicitly enabled completion-record policy. Disabled options return an
// inert mark, preserving strict decode costs.
func (bb *BitBuffer) RecoveryComponent(name string) int {
	if bb.trace == nil || bb.trace.recovery == nil && bb.trace.padding == nil && bb.trace.empty == nil {
		return -1
	}
	return bb.trace.enter(pathSegment{name: name})
}

// RecoveryIndex is the list-index counterpart of RecoveryComponent.
// It leaves the path unchanged when these record policies are disabled.
func (bb *BitBuffer) RecoveryIndex(index int64) int {
	if bb.trace == nil || bb.trace.recovery == nil && bb.trace.padding == nil && bb.trace.empty == nil {
		return -1
	}
	return bb.trace.enter(pathSegment{index: index})
}
