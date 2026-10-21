// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/bounded_cost_test.go; SHA-256 2892ec9a74ee7f3782848feb955d5035e5da03ea27916940031d637997623685.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	goruntime "runtime"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// These are operational bounds, not ASN.1 value constraints. The synthetic
// encodings follow X.690 (02/2021) §§8.3, 8.19 and 8.23. A linear byte ceiling
// also catches one large allocation, which an allocation-count test misses.
func boundedCostBytes(t *testing.T, size, factor int, operation func()) uint64 {
	t.Helper()
	goruntime.GC()
	var before, after goruntime.MemStats
	goruntime.ReadMemStats(&before)
	for range 5 {
		operation()
	}
	goruntime.ReadMemStats(&after)
	used := (after.TotalAlloc - before.TotalAlloc) / 5
	if used > uint64(factor*size+32768) {
		t.Fatalf("size=%d allocated=%d exceeds %d*n+32768", size, used, factor)
	}
	t.Logf("size=%d allocated=%d", size, used)
	return used
}

func boundedCostWire(t *testing.T, number int, constructed bool, content []byte) []byte {
	t.Helper()
	wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: number, Constructed: constructed}, content)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func boundedCostWork(t *testing.T, wire []byte) {
	t.Helper()
	for _, delta := range []int{-1, 0, 1} {
		err := ValidateBERElement(wire, WithDecodeLimits(DecodeLimits{MaxWork: len(wire) + delta}))
		if delta < 0 {
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("below byte boundary: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBEROIDByteLengthBound(t *testing.T) {
	for _, size := range []int{4096, 8192, 16384} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// One arbitrarily large second arc; no decimal materialization is needed.
			content := bytes.Repeat([]byte{0x81}, size)
			content[len(content)-1] = 1
			wire := boundedCostWire(t, tag.TagObjectID, false, content)
			boundedCostWork(t, wire)
			boundedCostBytes(t, len(wire), 8, func() {
				value, n, err := DecodeObjectIdentifier(wire)
				if err != nil || n != len(wire) {
					t.Fatalf("decode: %d %v", n, err)
				}
				encoded, err := EncodeObjectIdentifier(value)
				if err != nil || !bytes.Equal(encoded, wire) {
					t.Fatal("OID replay", err)
				}
				if err := ValidateDERElement(encoded); err != nil {
					t.Fatal(err)
				}
			})
			bad := bytes.Clone(wire)
			bad[len(bad)-1] |= 128
			boundedCostBytes(t, len(bad), 4, func() {
				if _, _, err := DecodeObjectIdentifier(bad); err == nil {
					t.Fatal("unterminated arc accepted")
				}
			})
		})
	}
}

func TestBERIntegerMagnitudeBound(t *testing.T) {
	for _, size := range []int{4096, 8192, 16384} {
		for _, negative := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", size, negative), func(t *testing.T) {
				content := bytes.Repeat([]byte{0x55}, size)
				if negative {
					content[0] = 0xaa
				}
				wire := boundedCostWire(t, tag.TagInteger, false, content)
				boundedCostWork(t, wire)
				boundedCostBytes(t, len(wire), 16, func() {
					value, n, err := DecodeBigInt(wire)
					if err != nil || n != len(wire) {
						t.Fatalf("decode: %d %v", n, err)
					}
					encoded, err := EncodeBigInt(value)
					if err != nil || !bytes.Equal(encoded, wire) {
						t.Fatal("INTEGER replay", err)
					}
					if err := ValidateDERElement(encoded); err != nil {
						t.Fatal(err)
					}
				})
				sign := byte(0)
				if negative {
					sign = 255
				}
				bad := boundedCostWire(t, tag.TagInteger, false, append([]byte{sign}, content...))
				boundedCostBytes(t, len(bad), 4, func() {
					if _, _, err := DecodeBigInt(bad); err == nil {
						t.Fatal("redundant sign accepted")
					}
				})
				if _, _, err := DecodeBigInt(wire[:len(wire)-1]); !errors.Is(err, ErrTruncated) {
					t.Fatalf("truncated magnitude: %v", err)
				}
			})
		}
	}
}

func TestBERUTF8SegmentsBound(t *testing.T) {
	for _, size := range []int{1024, 2048, 4096} {
		for _, shape := range []string{"flat", "segments", "nested", "empty"} {
			t.Run(fmt.Sprintf("%s/%d", shape, size), func(t *testing.T) {
				content := bytes.Repeat([]byte("€"), size)
				wire := boundedCostWire(t, tag.TagUTF8String, false, content)
				if shape != "flat" {
					segment := []byte{4, 3, 0xe2, 0x82, 0xac}
					if shape == "empty" {
						segment = []byte{4, 0}
						content = nil
					}
					wire = boundedCostWire(t, tag.TagUTF8String, true, bytes.Repeat(segment, size))
					if shape == "nested" {
						inner := boundedCostWire(t, tag.TagOctetString, true, bytes.Repeat(segment, size))
						for range 31 {
							inner = boundedCostWire(t, tag.TagOctetString, true, inner)
						}
						wire = boundedCostWire(t, tag.TagUTF8String, true, inner)
					}
				}
				boundedCostWork(t, wire)
				boundedCostBytes(t, len(wire), 32, func() {
					budget, err := newBERWorkBudget([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: len(wire)})})
					if err != nil {
						t.Fatal(err)
					}
					var decoded []byte
					n, _, err := decodeStringSegments(wire, tag.TagUTF8String, 0, &budget, &decoded)
					if err != nil || n != len(wire) || budget.bytes != len(wire) || !bytes.Equal(decoded, content) {
						t.Fatalf("segments: n=%d work=%d err=%v", n, budget.bytes, err)
					}
					got, n, err := DecodeString(wire, tag.TagUTF8String)
					if err != nil || n != len(wire) || got != string(content) {
						t.Fatalf("UTF8: %d %v", n, err)
					}
				})
			})
		}
		// X.690 §8.23.3 allows a character's octets to straddle OCTET STRING
		// segments; §8.23.10 still requires the concatenation to be valid UTF-8.
		split := []byte{4, 1, 0xe2, 4, 2, 0x82, 0xac}
		wire := boundedCostWire(t, tag.TagUTF8String, true, bytes.Repeat(split, size))
		boundedCostWork(t, wire)
		if _, _, err := DecodeString(wire, tag.TagUTF8String); err != nil {
			t.Fatal(err)
		}
		wire[len(wire)-1] = 255
		boundedCostBytes(t, len(wire), 32, func() {
			if _, _, err := DecodeString(wire, tag.TagUTF8String); err == nil {
				t.Fatal("invalid late UTF8 accepted")
			}
		})
	}
}

func TestBEROpaqueDimensionsBound(t *testing.T) {
	for _, scale := range []int{1, 2, 4} {
		for _, shape := range []string{"width", "depth", "size"} {
			t.Run(fmt.Sprintf("%s/%d", shape, scale), func(t *testing.T) {
				wire := boundedCostWire(t, tag.TagOctetString, false, bytes.Repeat([]byte{1}, 1024*scale))
				if shape == "width" {
					wire = boundedCostWire(t, tag.TagSequence, true, bytes.Repeat([]byte{5, 0}, 1024*scale))
				}
				if shape == "depth" {
					wire = []byte{5, 0}
					for range 16 * scale {
						wire = append(append([]byte{0x30, 0x80}, wire...), 0, 0)
					}
				}
				boundedCostWork(t, wire)
				boundedCostBytes(t, len(wire), 64, func() {
					if err := ValidateBEREncodedElement(wire); err != nil {
						t.Fatal(err)
					}
				})
				// A malformed final child must fail without allocating a copy of every prefix.
				bad := boundedCostWire(t, tag.TagSequence, true, append(bytes.Clone(wire), 4, 1))
				boundedCostBytes(t, len(bad), 64, func() {
					if err := ValidateBERElement(bad); err == nil {
						t.Fatal("late truncation accepted")
					}
				})
			})
		}
	}
}

func TestGeneratedInputBytePreflightBound(t *testing.T) {
	for _, size := range []int{1 << 20, 2 << 20, 4 << 20, 16 << 20} {
		wire := boundedCostWire(t, tag.TagOctetString, false, make([]byte, size))
		for _, mode := range []string{"adaptive", "light", "proof"} {
			t.Run(fmt.Sprintf("%s/%d", mode, size), func(t *testing.T) {
				boundedCostBytes(t, 0, 0, func() {
					options := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: 4096})}
					if size == 16<<20 {
						options = nil
					} // Larger than the default once the header is included.
					if mode == "light" {
						options = append(options, ForceGeneratedBERLightForTesting())
					}
					if mode == "proof" {
						options = append(options, ForceGeneratedBERProofForTesting())
					}
					options = TrackBERForm(options)
					owned, err := OwnGeneratedBERInput(wire, options)
					if err == nil {
						_, _, err = PrepareGeneratedBERInput(owned, options)
					}
					if !errors.Is(err, ErrResourceLimit) {
						t.Fatalf("oversized input: %v", err)
					}
				})
			})
		}
	}
}
