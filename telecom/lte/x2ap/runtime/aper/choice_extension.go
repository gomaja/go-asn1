// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/choice_extension.go; SHA-256 25db5eabc620438461ebfa60d18a6c8b8fe70f209a11ccf524ea0f169aab4f9c.
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
	origin := raw.CaptureOrigin()
	origin.SourceVersion = "V19.1.0"
	origin.Location.Path = "UnknownExtension"
	return ChoiceExtension{index: index, contents: raw.bytes, image: raw.image, origin: origin, contentLocation: raw.CaptureContentLocation()}, nil
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

// EncodeTo emits opaque contents without allocating a temporary accessor copy.
// X.691 (02/2021) §23.8 requires complete open-type framing.
func (v ChoiceExtension) EncodeTo(bb *BitBuffer) error {
	if v.image.Present() {
		return v.image.encodeOpenTo(bb)
	}
	return EncodeOpenTypeAligned(bb, v.contents)
}

// ChildDecodeBuffer interprets a known alternative without an accessor copy.
// The parent retains the same finite operation budget and original-input map.
func (v ChoiceExtension) ChildDecodeBuffer(parent *BitBuffer) *BitBuffer {
	if v.image.Present() {
		return v.image.decodeBuffer(parent)
	}
	if parent == nil {
		child := NewBitBufferFromBytes(append([]byte(nil), v.contents...))
		child.nested = true
		if err := child.MapOriginalLocation(child.data, v.contentLocation); err != nil {
			child.decodeBudget().err = err
		}
		return child
	}
	if err := ChargeValue(parent, BitBuffer{}); err != nil {
		return NewNestedDecodeBuffer(nil, parent)
	}
	child := NewOwnedNestedDecodeBuffer(v.contents, parent)
	if err := child.MapOriginalLocation(v.contents, v.contentLocation); err != nil {
		child.decodeBudget().err = err
	}
	return child
}

// ObserveUnknown publishes an observation only after source-bound dispatch has
// established that the alternative is outside the pinned schema (X.691 §23.8).
// Known additions use ChildDecodeBuffer and never consume a report record.
func (v ChoiceExtension) ObserveUnknown(parent *BitBuffer) error {
	if parent == nil {
		return ErrInvalidValue
	}
	return (OpaqueOpenType{parent: parent, origin: v.origin}).Observe(UnknownExtension)
}
