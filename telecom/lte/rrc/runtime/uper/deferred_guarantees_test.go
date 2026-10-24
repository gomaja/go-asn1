// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/deferred_guarantees_test.go; SHA-256 1f09124f69c0f256d7a697c2f32bda1cd9196ccd4774605648274a1581774fda.
package uper

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Synthetic reproducer for go-asn1 #214: 101 is three bits regardless of
// the unused low five bits in the caller's octet.
func TestDeferBitsReproducer(t *testing.T) {
	raw := []byte{0xaf}
	final := NewBitBufferFromBytes(nil).EnterContained().DeferBits(raw, 3, nil)
	d := final.Deferred()
	if got := d.Bytes(); !bytes.Equal(got, []byte{0xa0}) || d.BitLength() != 3 || d.Err() != nil {
		t.Fatalf("Bytes()=%x BitLength()=%d Err()=%v", got, d.BitLength(), d.Err())
	}
	if raw[0] != 0xaf {
		t.Fatal("DeferBits or Bytes mutated the caller's slice")
	}
	invalid := NewBitBufferFromBytes(nil).EnterContained().DeferBits(raw, 12, nil).Deferred()
	if !errors.Is(invalid.Err(), ErrInvalidValue) {
		t.Fatalf("12 bits in one octet: %v", invalid.Err())
	}
}

func TestDeferredBytesMasksOnlyItsCopy(t *testing.T) {
	for bits := 1; bits <= 16; bits++ {
		for octet := 0; octet <= 255; octet++ {
			raw := bytes.Repeat([]byte{byte(octet)}, (bits+7)/8)
			original := bytes.Clone(raw)
			final := ContainedSite{}.DeferBits(raw, bits, nil)
			d := final.Deferred()
			want := bytes.Clone(raw)
			if bits%8 != 0 {
				want[len(want)-1] &= 0xff << uint(8-bits%8)
			}
			got := d.Bytes()
			if !bytes.Equal(got, want) || !bytes.Equal(raw, original) {
				t.Fatalf("%d/%x: got %x want %x, caller %x", bits, original, got, want, raw)
			}
			got[0] ^= 0xff
			if !bytes.Equal(d.Bytes(), want) {
				t.Fatal("Bytes exposes its storage")
			}
			raw[0] ^= 0xff
			if bytes.Equal(d.Bytes(), want) {
				t.Fatal("DeferBits copied the caller's slice")
			}
			raw[0] ^= 0xff
			bb, err := d.BitBuffer(DecodeOptions{})
			if err != nil {
				t.Fatalf("BitBuffer %d/%x: %v", bits, raw, err)
			}
			read, err := bb.ReadBitsToBytes(bits)
			if err != nil || !bytes.Equal(read, want) || bb.BitsRemaining() != 0 {
				t.Fatalf("BitBuffer read %x: %v", read, err)
			}
			out := NewBitBuffer()
			if err := out.WriteBit(1); err != nil {
				t.Fatal(err)
			}
			shell := &testShell{PERPadding_: final}
			if err := AppendDeferred(out, shell, final); err != nil {
				t.Fatal(err)
			}
			received, err := NewBitBufferFromBits(out.Bytes(), bits+1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := received.ReadBit(); err != nil {
				t.Fatal(err)
			}
			replay, err := received.ReadBitsToBytes(bits)
			if err != nil || !bytes.Equal(replay, want) {
				t.Fatalf("replay %x want %x: %v", replay, want, err)
			}
		}
	}
	// OCTET STRING contents are not a partial bit string.
	if got := (ContainedSite{}).DeferOctets([]byte{0xaf}, nil).Deferred().Bytes(); !bytes.Equal(got, []byte{0xaf}) {
		t.Fatalf("octets = %x", got)
	}
	for _, raw := range [][]byte{nil, {}} {
		d := (ContainedSite{}).DeferBits(raw, 0, nil).Deferred()
		bb, err := d.BitBuffer(DecodeOptions{})
		if d.Err() != nil || d.BitLength() != 0 || len(d.Bytes()) != 0 || err != nil || bb.BitsRemaining() != 0 {
			t.Fatalf("empty bits: %+v, %v", d, err)
		}
	}
}

func TestDeferBitsInvalidLength(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		bits int
	}{
		{"negative", []byte{0xaf}, -1}, {"negative-octet", nil, -8}, {"min-int", nil, math.MinInt},
		{"missing", nil, 1}, {"zero-with-octet", []byte{0xaf}, 0},
		{"short", []byte{0xaf}, 9}, {"reproducer", []byte{0xaf}, 12}, {"short-whole", []byte{0xaf}, 16},
		{"long", []byte{0xaf, 0xff}, 3}, {"long-whole", []byte{0xaf, 0xff}, 8},
		{"max-int", []byte{0xaf}, math.MaxInt},
	}
	cause := errors.New("contained decode failed")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, decodeErr := range []error{nil, cause} {
				for _, traced := range []bool{false, true} {
					var log DeferralLog
					bb := NewBitBufferFromBytes([]byte{0x80})
					if _, err := bb.ReadBit(); err != nil {
						t.Fatal(err)
					}
					if traced {
						if err := bb.SetDecodeOptions(DecodeOptions{ContainedDecoding: DeferAll, Deferrals: &log}); err != nil {
							t.Fatal(err)
						}
						bb.EnterComponent("Bits")
					}
					original := bytes.Clone(tc.raw)
					final := bb.EnterContained().DeferBits(tc.raw, tc.bits, decodeErr)
					d := final.Deferred()
					if !errors.Is(d.Err(), ErrInvalidValue) || (decodeErr != nil && !errors.Is(d.Err(), cause)) {
						t.Errorf("Err = %v", d.Err())
					}
					if d.BitLength() != tc.bits || !bytes.Equal(tc.raw, original) {
						t.Fatal("invalid construction changed the declared length or caller storage")
					}
					if got := d.Bytes(); got != nil {
						t.Errorf("invalid contents returned: %x", got)
					}
					if traced {
						if _, err := CaptureFinalBits(bb, "Root"); err != nil {
							t.Fatal(err)
						}
						records := log.Snapshot()
						if len(records) != 1 {
							t.Fatalf("records = %+v", records)
						}
						record := records[0]
						if record.Path != "Root.Bits" || record.Kind != BitStringContainer || record.BitLength != tc.bits || record.Err != d.Err() {
							t.Fatalf("record = %+v; deferred = %+v", record, d)
						}
						if d.Err() == nil || !strings.HasPrefix(d.Err().Error(), "decoding Root.Bits: ") {
							t.Errorf("unqualified deferred error: %v", d.Err())
						}
						if !errors.Is(record.Err, ErrInvalidValue) || (decodeErr != nil && !errors.Is(record.Err, cause)) {
							t.Errorf("record error = %v", record.Err)
						}
					}
					read, err := d.BitBuffer(DecodeOptions{})
					if read != nil || err != d.Err() {
						t.Errorf("BitBuffer = %v, %v; want stored error %v", read, err, d.Err())
					}
					shell := &testShell{PERPadding_: final}
					raw, err := MarshalDeferred(shell, final)
					if raw != nil || err != d.Err() {
						t.Errorf("MarshalDeferred = %x, %v; want stored error %v", raw, err, d.Err())
					}
					out := NewBitBuffer()
					if err := out.WriteBit(1); err != nil {
						t.Fatal(err)
					}
					if err := AppendDeferred(out, shell, final); err != d.Err() {
						t.Errorf("AppendDeferred = %v; want stored error %v", err, d.Err())
					}
					if out.BitsWritten() != 1 || !bytes.Equal(out.Bytes(), []byte{0x80}) {
						t.Fatal("invalid deferred value wrote output")
					}
				}
			}
		})
	}
}

func TestDeferredDecodeErrorStillReplays(t *testing.T) {
	// ErrInvalidValue from the abandoned inner decode is not a length error.
	final := ContainedSite{}.DeferBits([]byte{0xaf}, 3, ErrInvalidValue)
	shell := &testShell{PERPadding_: final}
	out := NewBitBuffer()
	if err := AppendDeferred(out, shell, final); err != nil || out.BitsWritten() != 3 || !bytes.Equal(out.Bytes(), []byte{0xa0}) {
		t.Fatalf("replay = %x/%d, %v", out.Bytes(), out.BitsWritten(), err)
	}
	if _, err := final.Deferred().BitBuffer(DecodeOptions{}); err != nil {
		t.Fatal(err)
	}
	octets := ContainedSite{}.DeferOctets([]byte{0xaf}, ErrInvalidValue)
	shell.PERPadding_ = octets
	if raw, err := MarshalDeferred(shell, octets); err != nil || !bytes.Equal(raw, []byte{0xaf}) {
		t.Fatalf("octets = %x, %v", raw, err)
	}
}

func TestDeferBitsDoesNotAllocateForContents(t *testing.T) {
	var final FinalPadding
	for _, size := range []int{1, 1024, 65536} {
		raw := make([]byte, size)
		allocations := testing.AllocsPerRun(100, func() { final = ContainedSite{}.DeferBits(raw, size*8-1, nil) })
		if allocations != 2 {
			t.Fatalf("size %d: %g allocations, want the two existing state allocations", size, allocations)
		}
		if len(final.Deferred().raw) != size || &final.Deferred().raw[0] != &raw[0] {
			t.Fatal("DeferBits did not retain the caller's slice")
		}
	}
}

// An OCTET STRING whose octet count fits int can still overflow its bit count
// on a 32-bit target. Its diagnostic length must not be mistaken for valid bits.
func TestDeferOctetsRejectsBitLengthOverflow386(t *testing.T) {
	if strconv.IntSize != 32 {
		t.Skip("requires 32-bit int")
	}
	raw := make([]byte, math.MaxInt/8+1)
	cause := errors.New("contained decode failed")
	final := ContainedSite{}.DeferOctets(raw, cause)
	d := final.Deferred()
	if !errors.Is(d.Err(), ErrInvalidValue) || !errors.Is(d.Err(), cause) {
		t.Fatalf("overflowing octets: %v", d.Err())
	}
	if d.BitLength() != math.MaxInt || d.Bytes() != nil {
		t.Fatal("overflowing contents exposed as a valid length")
	}
	shell := &testShell{PERPadding_: final}
	if encoded, err := MarshalDeferred(shell, final); encoded != nil || err != d.Err() {
		t.Fatalf("overflowing octets encoded: %v", err)
	}
}
