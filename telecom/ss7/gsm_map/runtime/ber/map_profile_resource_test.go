// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/map_profile_resource_test.go; SHA-256 ee1e9f78860344f93eb93c1609145efa0d043a62e1349a04bfb14fd9ececc20d.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestMAPProfileNestedSegmentBudget(t *testing.T) {
	// Default report limits must bound fragment metadata even when every
	// fragment has a nonminimal header at depth 100 (TS 29.002 §17.1.1).
	previous := make(map[bool]uint64)
	for _, count := range []int{1024, 4096, 16384} {
		for _, tolerant := range []bool{false, true} {
			name := "strict"
			if tolerant {
				name = "tolerant"
			}
			t.Run(fmt.Sprintf("%s/%d", name, count), func(t *testing.T) {
				wire := bytes.Repeat([]byte{0x24, 0x80}, 100)
				wire = append(wire, bytes.Repeat([]byte{4, 0x81, 0}, count)...)
				wire = append(wire, make([]byte, 200)...)
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				rows, err := profileDecode(t, wire, tolerant, func(opts []DecodeOption, data []byte) {
					if _, _, err := DecodeOctetString(data, opts...); err != nil {
						t.Fatal(err)
					}
				})
				runtime.ReadMemStats(&after)
				allocated := after.TotalAlloc - before.TotalAlloc
				t.Logf("wire=%d allocated=%d duration=%s error=%v", len(wire), allocated, time.Since(start), err)
				want := ErrInvalidValue
				if tolerant {
					want = ErrResourceLimit
				}
				if len(rows) != 0 {
					t.Fatalf("failed stage published %d reports", len(rows))
				}
				if !errors.Is(err, want) {
					t.Fatalf("error=%v, want %v", err, want)
				}
				if allocated > 64<<20 {
					t.Fatalf("diagnostic metadata allocated %d bytes for %d wire bytes", allocated, len(wire))
				}
				if prior := previous[tolerant]; prior != 0 && allocated > 5*prior+1<<20 {
					t.Fatalf("fourfold fragment growth allocated %d bytes after %d", allocated, prior)
				}
				previous[tolerant] = allocated
			})
		}
	}
}
