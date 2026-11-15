//go:build !race

// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/diagnostic_path_allocation_test.go; SHA-256 9462325f4efd01e079a3a1e64397341fb6e879007c7f06bf1c6bea5dd9565b0f.
package ber

import (
	"errors"
	"testing"
)

func TestDiagnosticPathStorageGrowsLinearly(t *testing.T) {
	var previous int64
	for _, depth := range []int{128, 256, 512} {
		wire := []byte{0x0c, 2, 0xc0, 0x80}
		for range depth {
			wire = append(append([]byte{0x30}, EncodeLength(len(wire))...), wire...)
		}
		options := TrackTCAPForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: depth + 8, MaxElements: depth + 8, MaxWork: len(wire) * 2})}, "Begin", "TCAPMessages", "Begin")
		if err := ValidateBERElement(wire, options...); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("depth %d: %v", depth, err)
		}
		result := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				if err := ValidateBERElement(wire, options...); err == nil {
					b.Fatal("invalid string accepted")
				}
			}
		})
		bytes := result.AllocedBytesPerOp()
		t.Logf("depth=%d diagnostic-bytes=%d", depth, bytes)
		if previous != 0 && bytes > 3*previous {
			t.Fatalf("doubling depth allocated %d bytes after %d", bytes, previous)
		}
		previous = bytes
	}
}
