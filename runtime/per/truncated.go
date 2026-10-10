package per

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

// ExtensionAdditions is the decode state of the extension additions of one
// SEQUENCE or SET value (X.691 (02/2021) 19.7 to 19.9). A generated decoder
// takes it with BeginExtensionAdditions before the value's extension bit,
// reads the extension bitmap through it, and asks Received before it reads
// the open type of each present addition. Without TruncatedExtensionTolerance
// it only keeps three bit positions and allocates nothing.
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
func (a *ExtensionAdditions) DecodeBitmapAligned(bb *BitBuffer) (int64, []bool, error) {
	return a.decodeBitmap(bb, DecodeExtensionBitmapAligned, true)
}

func (a *ExtensionAdditions) decodeBitmap(bb *BitBuffer, decode func(*BitBuffer) (int64, []bool, error), aligned bool) (int64, []bool, error) {
	a.root, a.aligned = bb.bitPos, aligned
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
func (a *ExtensionAdditions) Received(bb *BitBuffer, index int64) bool {
	if a.cut != nil {
		return false
	}
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
	record, err := a.cutRecord(append([]byte(nil), bb.data...), bb.bitLen, cutAt, offset, kept)
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
func (a *ExtensionAdditions) cutRecord(input []byte, bits, cutAt, offset int, kept bool) (*truncatedExtension, error) {
	reader, err := NewBitBufferFromBits(input, bits)
	if err != nil {
		return nil, err
	}
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
	return &truncatedExtension{input: input, bits: bits, expected: expected.data, expectedBits: expected.bitPos, kept: kept}, nil
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
	_, err := decodeLengthFragmentsBounded(&reader, aligned, math.MaxInt64, func(_ int64, length int64) error {
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
	return a.cut != nil && !a.cut.kept
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
	return f.bits != nil && f.bits.truncated != nil
}

// truncatedExtension is the record of a SEQUENCE or SET value whose extension
// addition was cut by the end of the input: a copy of the whole input, of
// bits bits, which the unchanged value re-encodes to, and the encoding the
// unchanged value gets up to its own end, of expectedBits bits. kept is set
// when an addition before the cut one was received, so the value keeps its
// extension bit and bitmap.
type truncatedExtension struct {
	input        []byte
	bits         int
	expected     []byte
	expectedBits int
	kept         bool
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
	if final.bits == nil || final.bits.truncated == nil {
		return
	}
	final.bits.truncated.replay(bb)
}

func (cut *truncatedExtension) replay(bb *BitBuffer) {
	if !cut.follows(bb) {
		return
	}
	bb.data = append(bb.data[:0], cut.input...)
	bb.bitPos = cut.bits
}

// follows reports whether bb holds exactly the encoding the unchanged value
// gets. A write buffer holds its bits in exactly the octets they need, with
// the unused low bits of the last one zero, as the expected encoding does.
func (cut *truncatedExtension) follows(bb *BitBuffer) bool {
	return bb.bitPos == cut.expectedBits && bytes.Equal(bb.data, cut.expected)
}
