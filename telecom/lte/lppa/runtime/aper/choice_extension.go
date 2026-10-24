// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/choice_extension.go; SHA-256 5df571c58aeb44ec92c714624ec04e8d0097eda99febeeb3861df326406b2253.
package aper

import (
	"math"
)

// ChoiceExtension owns an unknown CHOICE alternative. X.691 (02/2021) §23
// encodes the extension index and its complete open-type contents.
type ChoiceExtension struct {
	image    WireSpan
	index    int64
	contents []byte
	origin   OpaqueOrigin
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

// DecodeChoiceExtensionAligned reads one extension alternative and its source
// framing. X.691 (02/2021) §23.8 frames known additions the same way as unknown
// ones; only indexes beyond knownAlternatives are reported as unknown. Nested
// values use the reassembled fragment span map when present.
func DecodeChoiceExtensionAligned(bb *BitBuffer, index, knownAlternatives int64) (result0 ChoiceExtension, result1 error) {
	sourceStart := bb.BitPos()
	defer bb.locateDecodeFailure(sourceStart, "§23.8", &result1)

	if index < 0 || knownAlternatives < 0 {
		return ChoiceExtension{}, ErrInvalidValue
	}
	raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§23.8"})
	if err != nil {
		return ChoiceExtension{}, err
	}
	raw = raw.WithPath("UnknownExtension")
	if index >= knownAlternatives {
		if err := raw.Observe(UnknownExtension); err != nil {
			return ChoiceExtension{}, err
		}
	}
	origin := raw.Origin()
	origin.SourceVersion = "V19.0.0"
	if raw.image.Present() {
		return ChoiceExtension{index: index, image: raw.image, origin: origin}, nil
	}
	return ChoiceExtension{index: index, contents: raw.Bytes(), origin: origin}, nil
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
		data, err := v.image.ReplayBytes(bb.Budget())
		if err != nil {
			return err
		}
		return EncodeOpenTypeAligned(bb, data)
	}
	return EncodeOpenTypeAligned(bb, v.contents)
}

// ChildDecodeBuffer interprets a known alternative without an accessor copy.
// The parent retains the same finite operation budget and original-input map.
// With no parent, the reader owns a content copy and independent state.
func (v ChoiceExtension) ChildDecodeBuffer(parent *BitBuffer) *BitBuffer {
	if v.image.Present() {
		return v.image.decodeBuffer(parent)
	}
	if parent == nil {
		return NewBitBufferFromBytes(append([]byte(nil), v.contents...))
	}
	if err := ChargeValue(parent, BitBuffer{}); err != nil {
		return NewNestedDecodeBuffer(nil, parent)
	}
	return NewNestedDecodeBuffer(v.contents, parent)
}

func (v ChoiceExtension) ContentLength() uint64 {
	if v.image.Present() {
		return v.image.ByteLength()
	}
	return uint64(len(v.contents))
}
