// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/sequence_extension.go; SHA-256 0e819fc2e3d3bee319947fd738e8872a2df772132fb941c972953819d18b38d9.
package aper

import (
	"fmt"
	"math"
	"math/bits"
)

// IncrementCount records one bounded message element.
func IncrementCount[K comparable](counts map[K]int, key K) int {
	if counts[key] == math.MaxInt {
		return counts[key]
	}
	counts[key]++
	return counts[key]
}

// SequenceExtension is an owned unknown ASN.1 extension addition. X.691
// (02/2021) §§19.8–19.9 define its bitmap index and open-type contents.
type SequenceExtension struct {
	index    uint64
	contents []byte
	origin   OpaqueOrigin
}

func NewSequenceExtension(index uint64, contents []byte, origin OpaqueOrigin) SequenceExtension {
	origin.Location.Spans = append([]BitSpan(nil), origin.Location.Spans...)
	return SequenceExtension{index: index, contents: append([]byte(nil), contents...), origin: origin}
}

func (v SequenceExtension) Index() uint64    { return v.index }
func (v SequenceExtension) Contents() []byte { return append([]byte(nil), v.contents...) }
func (v SequenceExtension) Origin() OpaqueOrigin {
	origin := v.origin
	origin.Location.Spans = append([]BitSpan(nil), origin.Location.Spans...)
	return origin
}

// SequenceExtensionViews returns owned views of the received or caller-supplied
// additions. X.691 (02/2021) §§19.8–19.9 define the indexed bitmap.
func SequenceExtensionViews(present []bool, data [][]byte, origins []OpaqueOrigin) []SequenceExtension {
	var out []SequenceExtension
	for index, included := range present {
		if !included {
			continue
		}
		var contents []byte
		if index < len(data) {
			contents = data[index]
		}
		origin := OpaqueOrigin{Reason: CallerSupplied}
		if index < len(origins) {
			origin = origins[index]
		}
		if origin.Location.Path != "" {
			origin.Location.Path = Path(fmt.Sprintf("%s[%d]", origin.Location.Path, index))
		}
		out = append(out, NewSequenceExtension(uint64(index), contents, origin))
	}
	return out
}

// SetSequenceExtension updates private extension state after validating the
// bitmap index. X.691 (02/2021) §19.8 bounds the normally small index.
func SetSequenceExtension(count *int64, present *[]bool, data *[][]byte, origins *[]OpaqueOrigin, index uint64, contents []byte) error {
	if count == nil || present == nil || data == nil || origins == nil {
		return ErrInvalidValue
	}
	budget, err := BuildBudget()
	if err != nil {
		return err
	}
	bb := NewBudgetBuffer(budget)
	if index >= 16383 {
		return bb.resourceError("fragmented extension bitmap is unsupported")
	}
	if uint64(len(contents)) > bb.openTypeMaximum() {
		return bb.resourceError("open type bytes exceeded")
	}
	if err := bb.CheckOutput(uint64(len(contents))); err != nil {
		return err
	}
	if err := bb.ChargeAllocation(uint64(len(contents)), 1); err != nil {
		return err
	}

	length, carry := bits.Add64(index, 1, 0)
	if carry != 0 {
		return ErrInvalidValue
	}
	if uint64(len(*data)) < length {
		if err := ChargeSlice[[]byte](bb, length); err != nil {
			return err
		}
		next := make([][]byte, length)
		copy(next, *data)
		*data = next
	}
	if uint64(len(*present)) < length {
		if err := ChargeSlice[bool](bb, length); err != nil {
			return err
		}
		next := make([]bool, length)
		copy(next, *present)
		*present = next
	}
	if uint64(len(*origins)) < length {
		if err := ChargeSlice[OpaqueOrigin](bb, length); err != nil {
			return err
		}
		next := make([]OpaqueOrigin, length)
		copy(next, *origins)
		*origins = next
	}
	(*present)[index] = true
	(*data)[index] = append([]byte{}, contents...)
	(*origins)[index] = OpaqueOrigin{Reason: CallerSupplied}
	if int64(index) > *count {
		*count = int64(index)
	}
	return nil
}

// RemoveSequenceExtension drops an addition and recomputes the bitmap tail.
func RemoveSequenceExtension(count *int64, present *[]bool, data *[][]byte, origins *[]OpaqueOrigin, index uint64) error {
	if count == nil || present == nil || data == nil || origins == nil || index >= uint64(len(*present)) || index >= uint64(len(*data)) || !(*present)[index] {
		return ErrInvalidValue
	}
	(*present)[index] = false
	(*data)[index] = nil
	if index < uint64(len(*origins)) {
		(*origins)[index] = OpaqueOrigin{}
	}
	last := -1
	for i, included := range *present {
		if included {
			last = i
		}
	}
	if last < 0 {
		*count, *present, *data, *origins = 0, nil, nil, nil
		return nil
	}
	*count = int64(last)
	length, carry := bits.Add64(uint64(last), 1, 0)
	if carry != 0 {
		return ErrInvalidValue
	}
	*present = (*present)[:length]
	*data = (*data)[:length]
	if uint64(len(*origins)) > length {
		*origins = (*origins)[:length]
	}
	return nil
}

// ExtensionContents prepares private unknown contents only when an encoder or
// byte-returning accessor needs them. Decode retains the immutable spans.
func ExtensionContents(data [][]byte, spans []WireSpan) [][]byte {
	hasSpans := false
	for i, s := range spans {
		if s.Present() && (i >= len(data) || data[i] == nil) {
			hasSpans = true
			break
		}
	}
	if !hasSpans {
		return data
	}
	out := make([][]byte, max(len(data), len(spans)))
	copy(out, data)
	for i, s := range spans {
		if out[i] == nil && s.Present() {
			out[i] = s.Bytes()
		}
	}
	return out
}

// CopyExtensionContents prepares received unknown additions for an encoder
// under that encoder's operation budget, propagating every copy failure.
// X.691 (02/2021) §§19.8–19.9 encode their complete open contents.
func CopyExtensionContents(data [][]byte, spans []WireSpan, budget *DecodeBudget) ([][]byte, error) {
	hasSpans := false
	for i, s := range spans {
		if s.Present() && (i >= len(data) || data[i] == nil) {
			hasSpans = true
			break
		}
	}
	if !hasSpans {
		return data, nil
	}
	bb := NewBudgetBuffer(budget)
	if err := ChargeSlice[[]byte](bb, uint64(max(len(data), len(spans)))); err != nil {
		return nil, err
	}
	out := make([][]byte, max(len(data), len(spans)))
	copy(out, data)
	for i, s := range spans {
		if out[i] == nil && s.Present() {
			contents, err := CopyReplay(s, budget)
			if err != nil {
				return nil, err
			}
			out[i] = contents
		}
	}
	return out, nil
}
