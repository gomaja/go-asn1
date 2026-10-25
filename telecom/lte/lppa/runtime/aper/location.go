// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/location.go; SHA-256 1a0dd84b889d03d0ad6a6f21d22f6d86b11e0586d15932a65421a27215784634.
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
// wire span. 3GPP TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.
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
	image    WireSpan
	present  bool
	original []byte
	location Location
	padding  []PaddingSpan
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
