// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/linear_encoder.go; SHA-256 62fafabeb884efbd8b2fe4b7544ca29650a6f49916480455ba27c16483917d11.
package ber

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

type linearInsertion struct {
	position int
	extra    uint64
}

type linearSortFrame struct {
	position int
	final    int
	setOf    bool
}

type linearSortElement struct {
	tag  tag.Tag
	wire []byte
}

// LinearFrame identifies one constructed TLV in a LinearEncoder.
type LinearFrame struct {
	lengthAt       int
	tagSize        int
	startSize      int
	depth          int
	insertionIndex int
	indefinite     bool
}

// LinearEncoder builds nested definite-length TLVs in one buffer. Each frame
// reserves one length octet and records its position when the frame begins.
// A long-form length adds its remaining octets in one final linear copy.
// ITU-T X.690 (02/2021) §8.1.3 defines the length forms and
// §10.1 requires the shortest form for DER. Erratum 1 (09/2021) changes only
// Figure 4's high-tag-number identifier example.
type LinearEncoder struct {
	raw              []byte
	insertions       []linearInsertion
	sortFrames       []linearSortFrame
	sortElements     []linearSortElement
	usedSize         int
	depth            int
	err              error
	nextTag          tag.Tag
	hasNextTag       bool
	nextIndefinite   bool
	inlineRaw        [2048]byte
	inlineInsertions [1024]linearInsertion
	inlineSortFrames [128]linearSortFrame
	inlineSortItems  [16]linearSortElement
}

var linearEncoderPool = sync.Pool{New: func() any { return new(LinearEncoder) }}

func acquireLinearEncoder() *LinearEncoder {
	return linearEncoderPool.Get().(*LinearEncoder)
}

func releaseLinearEncoder(e *LinearEncoder) {
	if e == nil {
		return
	}
	// Clear references before deciding whether an oversized builder can be
	// pooled. A discarded builder must not retain caller-owned bytes.
	large := cap(e.raw) > 64<<10 || cap(e.insertions) > 4<<10
	clear(e.inlineSortItems[:])
	clear(e.sortElements)
	e.raw = e.inlineRaw[:0]
	e.insertions = e.inlineInsertions[:0]
	e.sortFrames = e.inlineSortFrames[:0]
	e.sortElements = e.inlineSortItems[:0]
	e.usedSize = 0
	e.depth = 0
	e.err = nil
	e.nextTag = tag.Tag{}
	e.hasNextTag = false
	e.nextIndefinite = false
	if !large {
		linearEncoderPool.Put(e)
	}
}

// EncodeLinear lends one builder to a generated BER or DER root encoder.
// The callback has exclusive ownership for one encoding rule; it must finish
// every frame and must not retain or copy the builder. EncodeLinear releases
// it exactly once, discards partial output on error, and returns owned bytes.
// ITU-T X.690 (02/2021) §§8.1.3, 10.1 require completed lengths before
// the output is returned. Generated public codecs validate options and
// prepare BER replay before entering this operation.
func EncodeLinear(appendValue func(*LinearEncoder) error) ([]byte, error) {
	if appendValue == nil {
		return nil, fmt.Errorf("%w: nil BER linear append function", ErrInvalidValue)
	}
	encoder := acquireLinearEncoder()
	defer releaseLinearEncoder(encoder)
	if err := appendValue(encoder); err != nil {
		return nil, err
	}
	return encoder.bytes()
}

// OverrideNextTag replaces the identifier of the next child element. An
// IMPLICIT component changes the identifier while retaining its contents
// (ITU-T X.690 (02/2021) §8.14.2). A received indefinite tagged collection
// keeps that length form when its enclosing value is edited.
func (e *LinearEncoder) OverrideNextTag(t tag.Tag, indefinite bool) {
	// Nested IMPLICIT tags replace the same outer identifier. The first
	// override comes from the outermost assignment and must prevail.
	// ITU-T X.690 (02/2021) §8.14.4.
	if e.hasNextTag {
		return
	}
	e.nextTag = t
	e.hasNextTag = true
	e.nextIndefinite = indefinite
}

func (e *LinearEncoder) init() {
	if e.raw == nil {
		e.raw = e.inlineRaw[:0]
		e.insertions = e.inlineInsertions[:0]
		e.sortFrames = e.inlineSortFrames[:0]
		e.sortElements = e.inlineSortItems[:0]
	}
}

// BeginDERSet marks a SET whose complete child encodings must be ordered by
// tag at the final output pass (ITU-T X.690 (02/2021) §10.3).
func (e *LinearEncoder) BeginDERSet(t tag.Tag) LinearFrame {
	return e.beginSorted(t, false)
}

// BeginDERSetOf orders complete element encodings by their octets (ITU-T
// X.690 (02/2021) §11.6).
func (e *LinearEncoder) BeginDERSetOf(t tag.Tag) LinearFrame {
	return e.beginSorted(t, true)
}

func (e *LinearEncoder) beginSorted(t tag.Tag, setOf bool) LinearFrame {
	frame := e.Begin(t)
	e.sortFrames = append(e.sortFrames, linearSortFrame{position: frame.lengthAt - frame.tagSize, setOf: setOf})
	return frame
}

// Begin starts a constructed TLV. Calls to End must be nested in reverse order.
func (e *LinearEncoder) Begin(t tag.Tag) LinearFrame {
	e.init()
	indefinite := false
	if e.hasNextTag {
		t = e.nextTag
		indefinite = e.nextIndefinite
		e.hasNextTag = false
		e.nextIndefinite = false
	}
	t.Constructed = true
	tagBytes := t.Encode()
	e.raw = append(e.raw, tagBytes...)
	frame := LinearFrame{lengthAt: len(e.raw), tagSize: len(tagBytes), startSize: e.usedSize, insertionIndex: len(e.insertions), indefinite: indefinite}
	e.insertions = append(e.insertions, linearInsertion{position: frame.lengthAt})
	e.raw = append(e.raw, 0)
	e.depth++
	frame.depth = e.depth
	return frame
}

// Append writes already-encoded octets into the current TLV.
func (e *LinearEncoder) Append(encoded []byte) {
	e.init()
	if e.hasNextTag {
		// An unchanged received child can finish without calling Begin. Retag
		// its complete TLV here, preserving its original length octets.
		_, total, content, err := DecodeEncodedTLV(encoded)
		if err != nil || total != len(encoded) {
			e.err = fmt.Errorf("%w: invalid implicitly tagged BER child", ErrInvalidValue)
			return
		}
		t := e.nextTag
		t.Constructed = encoded[0]&0x20 != 0
		indefinite := e.nextIndefinite
		e.hasNextTag = false
		e.nextIndefinite = false
		identifier := t.Encode()
		e.Append(identifier)
		if indefinite {
			e.Append([]byte{0x80})
			e.Append(content)
			e.Append([]byte{0, 0})
			return
		}
		oldIdentifierLength := 1
		if encoded[0]&0x1f == 0x1f {
			for oldIdentifierLength < len(encoded) {
				octet := encoded[oldIdentifierLength]
				oldIdentifierLength++
				if octet&0x80 == 0 {
					break
				}
			}
		}
		e.Append(encoded[oldIdentifierLength:])
		return
	}
	if e.err != nil {
		return
	}
	if len(encoded) > math.MaxInt-e.usedSize {
		e.err = fmt.Errorf("%w: BER output exceeds host int", ErrInvalidValue)
		return
	}
	e.raw = append(e.raw, encoded...)
	e.usedSize += len(encoded)
}

// AppendVerbatim writes a validated, retained BER extension element without
// changing its identifier, length form, contents or end-of-contents octets.
// ITU-T X.690 (02/2021) §§8.1.1, 8.1.3, 8.13.
func (e *LinearEncoder) AppendVerbatim(element []byte) {
	e.Append(element)
}

// AppendBoolean writes a BOOLEAN TLV without an intermediate byte slice.
// X.690 (02/2021) §8.2.2 permits a received nonzero TRUE octet in BER;
// callers pass zero for DER's canonical TRUE form (§11.1).
func (e *LinearEncoder) AppendBoolean(value bool, raw byte) {
	encoded := [3]byte{1, 1, 0}
	if value {
		encoded[2] = 0xff
		if raw != 0 {
			encoded[2] = raw
		}
	}
	e.Append(encoded[:])
}

// End fills the shortest definite length for the current constructed TLV.
func (e *LinearEncoder) End(frame LinearFrame) error {
	if e.err != nil {
		return e.err
	}
	if frame.depth <= 0 || frame.depth != e.depth || frame.lengthAt < 0 || frame.lengthAt >= len(e.raw) ||
		frame.startSize > e.usedSize || frame.insertionIndex < 0 || frame.insertionIndex >= len(e.insertions) ||
		e.insertions[frame.insertionIndex].position != frame.lengthAt {
		return fmt.Errorf("%w: invalid BER encoder frame", ErrInvalidValue)
	}
	contentSize := e.usedSize - frame.startSize
	if frame.indefinite {
		if _, err := checkedBERCapacity(math.MaxInt, e.usedSize, frame.tagSize, 3); err != nil {
			e.err = err
			return err
		}
		e.raw[frame.lengthAt] = 0x80
		e.raw = append(e.raw, 0, 0)
		e.usedSize += frame.tagSize + 3
		e.depth--
		return nil
	}
	var length [9]byte
	lengthSize := encodeLengthFixed(&length, contentSize)
	if _, err := checkedBERCapacity(math.MaxInt, e.usedSize, frame.tagSize, lengthSize); err != nil {
		e.err = err
		return err
	}
	e.raw[frame.lengthAt] = length[0]
	if lengthSize > 1 {
		var extra uint64
		for _, octet := range length[1:lengthSize] {
			extra = extra<<8 | uint64(octet)
		}
		e.insertions[frame.insertionIndex].extra = extra
	}
	e.usedSize += frame.tagSize + lengthSize
	e.depth--
	return nil
}

func encodeLengthFixed(dst *[9]byte, value int) int {
	if value < 128 {
		dst[0] = byte(value)
		return 1
	}
	octets := 0
	for remaining := value; remaining != 0; remaining >>= 8 {
		octets++
	}
	dst[0] = 0x80 | byte(octets)
	for i := octets; i > 0; i-- {
		dst[i] = byte(value)
		value >>= 8
	}
	return octets + 1
}

// bytes returns the completed TLV stream in one allocation. A small capacity
// reserve lets callers append a transport wrapper without copying the stream.
func (e *LinearEncoder) bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if e.depth != 0 {
		return nil, fmt.Errorf("%w: unfinished BER encoder frame", ErrInvalidValue)
	}
	capacity, err := checkedBERCapacity(math.MaxInt, e.usedSize, 64)
	if err != nil {
		capacity = e.usedSize
	}
	result := make([]byte, e.usedSize, capacity)
	rawOffset, resultOffset := 0, 0
	for _, insertion := range e.insertions {
		if e.raw[insertion.position] < 0x80 {
			continue
		}
		end := insertion.position + 1
		resultOffset += copy(result[resultOffset:], e.raw[rawOffset:end])
		octets := int(e.raw[insertion.position] & 0x7f)
		extra := insertion.extra
		for i := octets - 1; i >= 0; i-- {
			result[resultOffset+i] = byte(extra)
			extra >>= 8
		}
		resultOffset += octets
		rawOffset = end
	}
	resultOffset += copy(result[resultOffset:], e.raw[rawOffset:])
	if resultOffset != len(result) {
		return nil, fmt.Errorf("%w: inconsistent BER encoder length", ErrInvalidValue)
	}
	if err := e.sortDERFrames(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (e *LinearEncoder) sortDERFrames(result []byte) error {
	if len(e.sortFrames) == 0 {
		return nil
	}
	insert, growth := 0, 0
	for i := range e.sortFrames {
		frame := &e.sortFrames[i]
		for insert < len(e.insertions) && e.insertions[insert].position < frame.position {
			if octet := e.raw[e.insertions[insert].position]; octet >= 0x80 {
				if int(octet&0x7f) > len(result)-growth {
					return fmt.Errorf("%w: DER length growth exceeds output", ErrInvalidLength)
				}
				growth += int(octet & 0x7f)
			}
			insert++
		}
		if frame.position < 0 || frame.position > len(result) || growth > len(result)-frame.position {
			return fmt.Errorf("%w: invalid DER SET position", ErrInvalidValue)
		}
		frame.final = frame.position + growth
	}
	var scratch []byte
	for i := len(e.sortFrames) - 1; i >= 0; i-- {
		position := e.sortFrames[i].final
		if position < 0 || position >= len(result) {
			return fmt.Errorf("%w: invalid DER SET position", ErrInvalidValue)
		}
		_, _, content, err := linearDERElement(result[position:])
		if err != nil {
			return err
		}
		e.sortElements = e.sortElements[:0]
		for offset := 0; offset < len(content); {
			t, length, _, err := linearDERElement(content[offset:])
			if err != nil || length <= 0 || length > len(content)-offset {
				return fmt.Errorf("%w: invalid DER SET element", ErrInvalidValue)
			}
			e.sortElements = append(e.sortElements, linearSortElement{tag: t, wire: content[offset : offset+length]})
			offset += length
		}
		if len(e.sortElements) < 2 {
			continue
		}
		if e.sortFrames[i].setOf {
			slices.SortStableFunc(e.sortElements, func(a, b linearSortElement) int { return compareDEROctetStrings(a.wire, b.wire) })
		} else {
			slices.SortStableFunc(e.sortElements, func(a, b linearSortElement) int {
				if a.tag.Class != b.tag.Class {
					return cmp.Compare(a.tag.Class, b.tag.Class)
				}
				return cmp.Compare(a.tag.Number, b.tag.Number)
			})
		}
		if scratch == nil {
			scratch = make([]byte, len(result))
		}
		offset := 0
		for _, element := range e.sortElements {
			if len(element.wire) > len(content)-offset {
				return fmt.Errorf("%w: invalid DER SET element range", ErrInvalidValue)
			}
			offset += copy(scratch[offset:], element.wire)
		}
		copy(content, scratch[:offset])
	}
	return nil
}

// linearDERElement reads only an identifier and a definite length. The
// builder has already assembled complete child TLVs; recursive validation at
// every enclosing SET would revisit the same bytes and allocate per level.
// ITU-T X.690 (02/2021) §§8.1.2–8.1.3, 10.1.
func linearDERElement(data []byte) (tag.Tag, int, []byte, error) {
	t, tagLength, err := DecodeTag(data)
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}
	length, indefinite, lengthLength, err := DecodeLength(data[tagLength:])
	if err != nil {
		return tag.Tag{}, 0, nil, err
	}
	if indefinite || length > len(data)-tagLength-lengthLength {
		return tag.Tag{}, 0, nil, ErrInvalidLength
	}
	header := tagLength + lengthLength
	return t, header + length, data[header : header+length], nil
}
