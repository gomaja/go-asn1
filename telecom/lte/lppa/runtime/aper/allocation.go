// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/allocation.go; SHA-256 023a4096db68042d1799b18604218a697398c36dea1f0320c75c07d2c9515551.
package aper

import (
	"math"
	"unsafe"
)

// ChargeSlice reserves the requested backing storage, checking the product.
func ChargeSlice[T any](bb *BitBuffer, count uint64) error {
	var value T
	return bb.ChargeAllocation(count, uint64(unsafe.Sizeof(value)))
}

// AppendValues uses explicit geometric growth, charging the replacement backing
// array and copied elements before allocation. It never refunds failed work.
func AppendValues[T any](bb *BitBuffer, current []T, values ...T) ([]T, error) {
	if len(values) > math.MaxInt-len(current) {
		return nil, bb.resourceError("slice length overflows host int")
	}
	needed := len(current) + len(values)
	if needed > cap(current) {
		capacity := needed
		if cap(current) <= math.MaxInt/2 {
			capacity = max(capacity, cap(current)*2)
		}
		if err := ChargeSlice[T](bb, uint64(capacity)); err != nil {
			return nil, err
		}
		next := make([]T, len(current), capacity)
		copy(next, current)
		current = next
	}
	var value T
	size := uint64(unsafe.Sizeof(value))
	count := uint64(len(values))
	if size != 0 && count > math.MaxUint64/size {
		return nil, bb.resourceError("copy work product overflows")
	}
	if err := bb.ChargeWork(count * size); err != nil {
		return nil, err
	}
	return append(current, values...), nil
}

// ChargeValue reserves one generated pointer-owned semantic value before it escapes.
func ChargeValue[T any](bb *BitBuffer, value T) error {
	return bb.ChargeAllocation(1, uint64(unsafe.Sizeof(value)))
}

// ReserveMapEntry charges a deterministic conservative entry request, including
// the table header and load-factor headroom. It does not model allocator classes.
func ReserveMapEntry[K comparable, V any](bb *BitBuffer, entries map[K]V, key K) error {
	if _, present := entries[key]; present {
		return nil
	}
	var k K
	var v V
	keySize, valueSize := uint64(unsafe.Sizeof(k)), uint64(unsafe.Sizeof(v))
	if keySize > math.MaxUint64-valueSize {
		return bb.resourceError("map entry size overflows")
	}
	size := keySize + valueSize
	if size > math.MaxUint64-32 {
		return bb.resourceError("map headroom overflows")
	}
	// Map key/value sizes are compile-time bounded for each generated instance.
	if err := bb.ChargeAllocation(2, size+32); err != nil {
		return err
	}
	if entries == nil {
		return bb.ChargeAllocation(1, 64)
	}
	return nil
}
