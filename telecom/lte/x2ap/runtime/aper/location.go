// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/location.go; SHA-256 f85afb64c86cd976d57f2f5c87fda34891886800958fd95bc3664ac84b188ffd.
package aper

import "math/bits"

// Path names the source-shaped member within a decoded or fresh value.
type Path string

// BitSpan describes a half-open span of the original complete encoding.
type BitSpan struct {
	Start uint64
	End   uint64
}

// Location identifies a source-shaped path and, when available, its received
// wire span. 3GPP TS 36.423 V19.1.0 §10 adopts TS 36.413 V19.2.0 §10.
type Location struct {
	Path            Path
	Spans           []BitSpan
	HasWireLocation bool
}

// PaddingSpan identifies observed terminal padding without exposing writable
// codec state (X.691 (02/2021) §§11.1.4 and 11.2.1).
type PaddingSpan struct {
	Span  BitSpan
	Value uint8
	Width uint8
}

// ReceivedForm is an immutable snapshot of a complete APER value as received.
type ReceivedForm struct {
	image      WireSpan
	present    bool
	original   []byte
	location   Location
	padding    []PaddingSpan
	fieldBits  int
	fieldPhase uint8
	field      bool
}

// CaptureFieldReceivedForm snapshots a decoded field and maps its bits back
// through any enclosing open-type fragments. X.691 (02/2021) §§11.2 and
// 11.9.3.8 define those boundaries. The complete field is packed MSB first.
func CaptureFieldReceivedForm(bb *BitBuffer, start int, path Path) (ReceivedForm, error) {
	if bb == nil || bb.invalidLength || start < 0 || bb.bitPos < start || bb.bitPos > bb.bitLen {
		return ReceivedForm{}, ErrInvalidValue
	}
	end := bb.bitPos
	width := end - start
	length, err := octetsForBitLength(width)
	if err != nil {
		return ReceivedForm{}, err
	}
	first, last := start/8, 0
	if end > 0 {
		last = (end - 1) / 8
	}
	logicalOctets, err := octetsForBitLength(bb.bitLen)
	if err != nil {
		return ReceivedForm{}, err
	}
	if length > 0 && (first >= logicalOctets || last >= logicalOctets) {
		return ReceivedForm{}, ErrInvalidValue
	}
	phase := uint(start % 8)
	if err := bb.ChargeAllocation(uint64(length), 2); err != nil {
		return ReceivedForm{}, err
	}
	packed := make([]byte, length)
	for i := range packed {
		index := first + i
		packed[i] = bb.readOctet(index) << phase
		if phase != 0 && index < last {
			packed[i] |= bb.readOctet(index+1) >> (8 - phase)
		}
	}
	if tail := width % 8; tail != 0 {
		packed[len(packed)-1] &= byte(255 << uint(8-tail))
	}
	spans, located := originalRange(bb, uint64(start), uint64(end))
	return ReceivedForm{present: true, original: packed, location: Location{Path: path, Spans: spans, HasWireLocation: located}, fieldBits: width, fieldPhase: uint8(phase), field: true}, nil
}

// ReplayFieldReceivedForm appends an unchanged received field only at its
// original alignment. Callers first compare the field's semantic selectors
// and value. A changed alignment requires ordinary source-aware encoding.
func ReplayFieldReceivedForm(bb *BitBuffer, form ReceivedForm) (bool, error) {
	if bb == nil {
		return false, ErrInvalidValue
	}
	if !form.present || !form.field || bb.bitPos < 0 || uint8(bb.bitPos%8) != form.fieldPhase {
		return false, nil
	}
	if err := bb.WriteBitsFromBytes(form.original, form.fieldBits); err != nil {
		return false, err
	}
	return true, nil
}

// NewReceivedForm owns the bytes and location supplied by a decoder.
func NewReceivedForm(present bool, original []byte, location Location, padding []PaddingSpan) ReceivedForm {
	location.Spans = append([]BitSpan(nil), location.Spans...)
	return ReceivedForm{present: present, original: append([]byte(nil), original...), location: location, padding: append([]PaddingSpan(nil), padding...)}
}

// NewCompleteReceivedForm records the framing of one complete APER value.
// X.691 (02/2021) §11.1.4 defines its terminal padding.
func NewCompleteReceivedForm(present bool, original []byte, path Path, absolute bool, complete interface{ Bits() (uint8, uint8) }) ReceivedForm {
	location := Location{Path: path}
	var padding []PaddingSpan
	if absolute {
		high, end := bits.Mul64(uint64(len(original)), 8)
		if high == 0 {
			location.HasWireLocation = true
			location.Spans = []BitSpan{{Start: 0, End: end}}
			value, count := complete.Bits()
			if count > 0 && len(original) > 0 {
				start, borrow := bits.Sub64(end, uint64(count), 0)
				if borrow == 0 {
					padding = []PaddingSpan{{Span: BitSpan{Start: start, End: end}, Value: value, Width: count}}
				}
			}
		}
	}
	return NewReceivedForm(present, original, location, padding)
}

func (f ReceivedForm) Present() bool { return f.present }
func (f ReceivedForm) OriginalBytes() []byte {
	if f.image.Present() {
		return f.image.Bytes()
	}
	return append([]byte(nil), f.original...)
}
func (f ReceivedForm) Location() Location {
	location := f.location
	location.Spans = append([]BitSpan(nil), location.Spans...)
	return location
}
func (f ReceivedForm) Padding() []PaddingSpan { return append([]PaddingSpan(nil), f.padding...) }

// NewReceivedSpanForm retains a decoder-owned immutable image. Bytes are copied
// only when a caller asks for them; diagnostic slices remain independently owned.
func NewReceivedSpanForm(present bool, image WireSpan, location Location, padding []PaddingSpan) ReceivedForm {
	location.Spans = append([]BitSpan(nil), location.Spans...)
	return ReceivedForm{present: present, image: image, location: location, padding: append([]PaddingSpan(nil), padding...)}
}
func NewCompleteReceivedSpanForm(present bool, image WireSpan, path Path, absolute bool, complete interface{ Bits() (uint8, uint8) }) ReceivedForm {
	location := Location{Path: path}
	var padding []PaddingSpan
	if absolute && image.Present() {
		location = image.ContentLocation()
		location.Path = path
		value, count := complete.Bits()
		if len(location.Spans) > 0 && count > 0 {
			last := location.Spans[len(location.Spans)-1]
			if uint64(count) <= last.End-last.Start {
				padding = []PaddingSpan{{Span: BitSpan{Start: last.End - uint64(count), End: last.End}, Value: value, Width: count}}
			}
		}
	}
	return NewReceivedSpanForm(present, image, location, padding)
}
