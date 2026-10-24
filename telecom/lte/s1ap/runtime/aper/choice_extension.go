// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/choice_extension.go; SHA-256 c1c6f947202f0c74519409635f15efcdb41f2b85d1d8094e38f9baf2b43a31a0.
package aper

import (
	"math"
)

// ChoiceExtension owns an unknown CHOICE alternative. X.691 (02/2021) §23
// encodes the extension index and its complete open-type contents.
type ChoiceExtension struct {
	image           WireSpan
	index           int64
	contents        []byte
	origin          OpaqueOrigin
	contentLocation Location
}

// NewChoiceExtension validates a caller-supplied alternative index and owns
// its contents without claiming received provenance.
func NewChoiceExtension(index uint64, contents []byte) (ChoiceExtension, error) {
	budget, err := BuildBudget()
	if err != nil {
		return ChoiceExtension{}, err
	}
	return BuildChoiceExtension(index, contents, budget)
}

// BuildChoiceExtension uses the enclosing builder's finite ceilings.
func BuildChoiceExtension(index uint64, contents []byte, budget *DecodeBudget) (ChoiceExtension, error) {
	bb := NewBudgetBuffer(budget)
	if index > math.MaxInt64 {
		return ChoiceExtension{}, bb.resourceError("CHOICE index exceeds int64 representation")
	}
	if err := bb.CheckOutput(uint64(len(contents))); err != nil {
		return ChoiceExtension{}, err
	}
	opaque, err := BuildOpaqueOpenType(contents, budget)
	if err != nil {
		return ChoiceExtension{}, err
	}
	return ChoiceExtension{index: int64(index), contents: opaque.bytes, origin: OpaqueOrigin{Reason: CallerSupplied}}, nil
}

// DecodeChoiceExtensionAligned reads one unknown alternative and its source
// framing. Nested values use the reassembled fragment span map when present.
func DecodeChoiceExtensionAligned(bb *BitBuffer, index int64) (result0 ChoiceExtension, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§23.8", &result1)

	if index < 0 {
		return ChoiceExtension{}, ErrInvalidValue
	}
	raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§23.8"})
	if err != nil {
		return ChoiceExtension{}, err
	}
	raw = raw.WithPath("UnknownExtension")
	origin := raw.Origin()
	origin.SourceVersion = "V19.2.0"
	origin.Location.Path = "UnknownExtension"
	if raw.image.Present() {
		return ChoiceExtension{index: index, image: raw.image, origin: origin}, nil
	}
	return ChoiceExtension{index: index, contents: raw.bytes, origin: origin, contentLocation: raw.ContentLocation()}, nil
}

func (v ChoiceExtension) Index() int64 { return v.index }
func (v ChoiceExtension) Contents() []byte {
	if v.image.Present() {
		return v.image.Bytes()
	}
	return append([]byte(nil), v.contents...)
}
func (v ChoiceExtension) Origin() OpaqueOrigin {
	origin := v.origin
	origin.Location.Spans = append([]BitSpan(nil), origin.Location.Spans...)
	return origin
}

// ChildDecodeBuffer decodes a known extension alternative through the same
// immutable original spans. A nil parent creates an independent reader.
// X.691 (02/2021) §§11.2.2 and 23 delimit it.
func (v ChoiceExtension) ChildDecodeBuffer(parent *BitBuffer) *BitBuffer {
	if v.image.Present() {
		return v.image.decodeBuffer(parent)
	}
	if parent == nil {
		return NewBitBufferFromBytes(append([]byte(nil), v.contents...))
	}
	child := NewNestedDecodeBuffer(v.contents, parent)
	if err := child.MapOriginalLocation(v.contents, v.contentLocation); err != nil {
		child.decodeBudget().err = err
	}
	return child
}

func (v ChoiceExtension) ObserveUnknown(parent *BitBuffer) error {
	if parent == nil {
		return ErrInvalidValue
	}
	return (OpaqueOpenType{parent: parent, origin: v.origin, image: v.image, bytes: v.contents}).Observe(UnknownExtension)
}
func (v ChoiceExtension) EncodeTo(bb *BitBuffer) error {
	if v.image.Present() {
		data, err := CopyReplay(v.image, bb.decodeBudget())
		if err != nil {
			return err
		}
		return EncodeOpenTypeAligned(bb, data)
	}
	return EncodeOpenTypeAligned(bb, v.contents)
}
