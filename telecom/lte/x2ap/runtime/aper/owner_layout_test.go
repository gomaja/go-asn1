// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owner_layout_test.go; SHA-256 af735292c3a55f549f93ad29421162477beed05e373200a000e1e77166b0b445.
package aper

import (
	"testing"
	"unsafe"
)

func TestReplayOwnerLayout(t *testing.T) {
	t.Logf("BitBuffer=%d arena=%d small=%d compact=%d medium=%d message=%d observation=%d", unsafe.Sizeof(BitBuffer{}), unsafe.Sizeof(semanticArena{}), unsafe.Sizeof(smallDecodeOwner{}), unsafe.Sizeof(compactDecodeOwner{}), unsafe.Sizeof(mediumDecodeOwner{}), unsafe.Sizeof(messageDecodeOwner{}), unsafe.Sizeof(Observation{}))
	if unsafe.Sizeof(uintptr(0)) == 8 && (unsafe.Sizeof(BitBuffer{}) != 64 || unsafe.Offsetof(BitBuffer{}.budget) != 48 || unsafe.Offsetof(BitBuffer{}.trace) != 56) {
		t.Fatal("BitBuffer layout grew")
	}
}
