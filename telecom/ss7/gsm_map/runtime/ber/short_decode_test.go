// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/short_decode_test.go; SHA-256 3a94e7d0255581752ee9df6f7562a2aa2773856cd9d28c976b2e157546967fd8.
package ber

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestShortDecodeHeaders(t *testing.T) {
	// Literal identifiers and lengths are independent of the encoder:
	// X.690 (02/2021) §§8.1.2.2, 8.1.3.4.
	for class := range 4 {
		for _, constructed := range []bool{false, true} {
			for number := range 31 {
				identifier := byte(class<<6 | number)
				if constructed {
					identifier |= 0x20
				}
				for length := range 128 {
					wire := []byte{identifier, byte(length)}
					got, n, err := DecodeTag(wire)
					if err != nil || n != 1 || got.Class != tag.Class(class) || got.Constructed != constructed || got.Number != number {
						t.Fatalf("identifier %02x: %+v %d %v", identifier, got, n, err)
					}
					size, indefinite, n, err := DecodeLength(wire[1:])
					if err != nil || n != 1 || indefinite || size != length {
						t.Fatalf("length %02x: %d %t %d %v", length, size, indefinite, n, err)
					}
				}
			}
		}
	}
}

func TestScanFrameChildIndexes(t *testing.T) {
	// A preceding valid child advances the live frame. Its successor's
	// diagnostics still use the received zero-based index, including after
	// stack growth. X.690 (02/2021) §§8.2.1, 8.9.
	for _, depth := range []int{1, 7, 8, 9, 16} {
		for _, indefinite := range []bool{false, true} {
			for index := range 4 {
				wire := []byte{1, 2, 0, 0} // BOOLEAN must contain exactly one octet.
				for range depth {
					contents := make([]byte, 0, index*2+len(wire))
					for range index {
						contents = append(contents, 5, 0)
					}
					contents = append(contents, wire...)
					if indefinite {
						wire = append(append([]byte{0x30, 0x80}, contents...), 0, 0)
					} else {
						var err error
						wire, err = EncodeSequence(contents)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				err := ValidateBERElement(wire)
				var element *ElementError
				if !errors.As(err, &element) || !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("depth=%d indefinite=%t index=%d: %v", depth, indefinite, index, err)
				}
				want := make([]int, depth)
				for n := range want {
					want[n] = index
				}
				if !reflect.DeepEqual(element.ChildIndexes(), want) {
					t.Fatalf("%s indexes=%v want=%v", err, element.ChildIndexes(), want)
				}
			}
		}
	}
}

// A moderately nested untrusted value must not spend more than 1,408 bytes
// of scan-stack storage on a 64-bit host (704 bytes on a 32-bit host).
// X.690 (02/2021) §8.9 permits this nesting; the storage ceiling is local.
func TestScannerStackAllocationBudget(t *testing.T) {
	wire := []byte{5, 0}
	for range 9 {
		var err error
		wire, err = EncodeSequence(wire)
		if err != nil {
			t.Fatal(err)
		}
	}
	measurement := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := ValidateBERElement(wire); err != nil {
				b.Fatal(err)
			}
		}
	})
	const maximum = 176 * (strconv.IntSize / 8)
	if measurement.AllocedBytesPerOp() > maximum {
		t.Fatalf("scan stack allocated %d bytes, limit %d", measurement.AllocedBytesPerOp(), maximum)
	}
	t.Logf("scan stack: %d bytes/op", measurement.AllocedBytesPerOp())
}
