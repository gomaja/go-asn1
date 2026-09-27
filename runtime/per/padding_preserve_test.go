package per

import (
	"bytes"
	"errors"
	"testing"
)

func TestCompletePaddingPreservesObservedBits(t *testing.T) {
	for _, read := range []struct {
		name string
		fn   func(*BitBuffer) (CompletePadding, error)
	}{
		{"top-level", CaptureFinalPadding},
		{"open-type", CaptureOpenTypePadding},
	} {
		t.Run(read.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0xaf})
			if value, err := bb.ReadBits(4); err != nil || value != 0xa {
				t.Fatalf("decoded value = %x, %v", value, err)
			}
			pad, err := read.fn(bb)
			if err != nil {
				t.Fatal(err)
			}
			out := NewBitBuffer()
			if err := out.WriteBits(0xa, 4); err != nil {
				t.Fatal(err)
			}
			wire, err := out.CompleteBytesWithPadding(pad)
			if err != nil || !bytes.Equal(wire, []byte{0xaf}) {
				t.Fatalf("re-encoded = %x, %v; want af", wire, err)
			}
			canonical, err := out.CompleteBytesWithPadding(CompletePadding{})
			if err != nil || !bytes.Equal(canonical, []byte{0xa0}) {
				t.Fatalf("new value = %x, %v; want a0", canonical, err)
			}
			if err := out.WriteBit(1); err != nil {
				t.Fatal(err)
			}
			if _, err := out.CompleteBytesWithPadding(pad); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("changed length error = %v, want invalid value", err)
			}
		})
	}
}

func TestCompletePaddingRejectsAppendedOctet(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0xaf, 0x00})
	_, _ = bb.ReadBits(4)
	if _, err := CaptureFinalPadding(bb); !errors.Is(err, ErrExtraData) {
		t.Fatalf("appended octet error = %v, want extra data", err)
	}
}

func FuzzCompletePaddingRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{{}, {0}, {0x8f}, {0xff}, {0x80, 0}} {
		f.Add(seed, uint8(1))
	}
	f.Fuzz(func(t *testing.T, wire []byte, prefixBits uint8) {
		if len(wire) > 1024 || prefixBits > 7 || len(wire) == 0 && prefixBits > 0 {
			t.Skip()
		}
		for _, capture := range []func(*BitBuffer) (CompletePadding, error){CaptureFinalPadding, CaptureOpenTypePadding} {
			reader := NewBitBufferFromBytes(wire)
			value, err := reader.ReadBits(int(prefixBits))
			if err != nil {
				continue
			}
			padding, err := capture(reader)
			if err != nil {
				continue
			}
			writer := NewBitBuffer()
			if err := writer.WriteBits(value, int(prefixBits)); err != nil {
				t.Fatal(err)
			}
			got, err := writer.CompleteBytesWithPadding(padding)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("round trip = %x, %v; want %x", got, err, wire)
			}
		}
	})
}
