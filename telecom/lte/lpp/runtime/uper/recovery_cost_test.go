// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/recovery_cost_test.go; SHA-256 74d1c5feaf48162b9ae18c18826078d39d668aef105f83a90083a83bc422537d.
package uper

import (
	"bytes"
	"fmt"
	"testing"
)

// Copying the shared parent prefix into every recovered list element makes
// both retained provenance and allocations quadratic in the element count.

func FuzzRecoveryLocalReplay(f *testing.F) {
	f.Add([]byte{0xa5, 0x80}, []byte{0x54}, uint8(3), uint8(9))
	f.Add([]byte{0}, []byte{0}, uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, input, surviving []byte, phaseByte, prefixByte uint8) {
		if len(input) == 0 || len(input) > 256 || len(surviving) == 0 || len(surviving) > 256 {
			t.Skip()
		}
		phase := int(phaseByte % 8)
		prefix := 24 + phase
		received := NewBitBuffer()
		if err := received.WriteBits(0, prefix); err != nil {
			t.Fatal(err)
		}
		if err := received.WriteBytes(input); err != nil {
			t.Fatal(err)
		}
		parent := NewBitBufferFromBytes(received.Bytes())
		parent.bitPos = prefix
		a := BeginExtensionAdditions(parent)
		a.recovered = true
		parent.bitPos += len(input) * 8
		expected, err := a.RecoveryEncoder(parent)
		if err != nil {
			t.Fatal(err)
		}
		if err := expected.WriteBytes(surviving); err != nil {
			t.Fatal(err)
		}
		final, err := a.RecordRecovery(parent, expected, FinalPadding{})
		if err != nil {
			t.Fatal(err)
		}
		encoded := NewBitBuffer()
		if err := encoded.WriteBits(uint64(prefixByte), prefix); err != nil {
			t.Fatal(err)
		}
		if err := encoded.WriteBytes(surviving); err != nil {
			t.Fatal(err)
		}
		AppendExtensionRecovery(encoded, final, prefix)
		reader := NewBitBufferFromBytes(encoded.Bytes())
		gotPrefix, err := reader.ReadBits(prefix)
		if err != nil || gotPrefix != uint64(prefixByte) {
			t.Fatalf("parent prefix changed: %x %v", gotPrefix, err)
		}
		got, err := reader.ReadBytes(len(input))
		if err != nil || !bytes.Equal(got, input) || encoded.BitsWritten() != prefix+len(input)*8 {
			t.Fatalf("local replay=%x want %x err=%v", got, input, err)
		}
	})
}

// X.691 (02/2021) 11.1.4: APER alignment depends on the starting bit
// position modulo eight, never on the values or size of the parent prefix.
func TestRecoveryProvenanceLocalContext(t *testing.T) {
	for phase := 0; phase < 8; phase++ {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			input := NewBitBuffer()
			if err := input.WriteBits(0, 24+phase); err != nil {
				t.Fatal(err)
			}
			if err := input.WriteBits(0xa55, 12); err != nil {
				t.Fatal(err)
			}
			parent := NewBitBufferFromBytes(input.Bytes())
			parent.bitPos = 24 + phase
			a := BeginExtensionAdditions(parent)
			a.recovered = true
			parent.bitPos += 12
			expected, err := a.RecoveryEncoder(parent)
			if err != nil {
				t.Fatal(err)
			}
			if err := expected.WriteBits(0x15, 5); err != nil {
				t.Fatal(err)
			}
			final, err := a.RecordRecovery(parent, expected, FinalPadding{})
			if err != nil {
				t.Fatal(err)
			}
			// A sibling edit or a relocation by whole octets cannot enlarge
			// this record or replace the prefix of the enclosing value.
			for _, prefix := range []int{24 + phase, 40 + phase} {
				encoded := NewBitBuffer()
				if err := encoded.WriteBits(^uint64(0), prefix); err != nil {
					t.Fatal(err)
				}
				if err := encoded.WriteBits(0x15, 5); err != nil {
					t.Fatal(err)
				}
				AppendExtensionRecovery(encoded, final, prefix)
				if encoded.BitsWritten() != prefix+12 {
					t.Fatal("local provenance depends on the parent prefix")
				}
				reader := NewBitBufferFromBytes(encoded.Bytes())
				gotPrefix, err := reader.ReadBits(prefix)
				if err != nil || gotPrefix != (uint64(1)<<uint(prefix))-1 {
					t.Fatal("replay changed the parent prefix")
				}
				got, err := reader.ReadBits(12)
				if err != nil || got != 0xa55 {
					t.Fatalf("local replay=%x %v", got, err)
				}
				if err := encoded.WriteBits(7, 3); err != nil {
					t.Fatal(err)
				}
			}
			parent.data[0] ^= 0xff
			parent.data[len(parent.data)-1] ^= 0xff
			encoded := NewBitBuffer()
			if err := encoded.WriteBits(0, phase); err != nil {
				t.Fatal(err)
			}
			if err := encoded.WriteBits(0x14, 5); err != nil {
				t.Fatal(err)
			}
			AppendExtensionRecovery(encoded, final, phase)
			if encoded.BitsWritten() != phase+5 {
				t.Fatal("edited local value replayed stale provenance")
			}
		})
	}
}

func TestRecoveryCombinedOuterCutKeepsPrefix(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0x7f, 0xa5})
	parent.bitPos = 8
	a := BeginExtensionAdditions(parent)
	a.cut, a.recovered = &truncatedExtension{}, true
	parent.bitPos = 16
	expected, err := a.RecoveryEncoder(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := expected.WriteBits(0x55, 8); err != nil {
		t.Fatal(err)
	}
	final, err := a.RecordRecovery(parent, expected, FinalPadding{})
	if err != nil || !final.Truncated() || !final.Recovered() {
		t.Fatalf("combined provenance=%+v %v", final, err)
	}
	for _, prefix := range []uint64{0x7f, 0x7e} {
		encoded := NewBitBuffer()
		if err := encoded.WriteBits(prefix, 8); err != nil {
			t.Fatal(err)
		}
		if err := encoded.WriteBits(0x55, 8); err != nil {
			t.Fatal(err)
		}
		AppendTruncatedExtension(encoded, final)
		want := byte(0x55)
		if prefix == 0x7f {
			want = 0xa5
		}
		if !bytes.Equal(encoded.Bytes(), []byte{byte(prefix), want}) {
			t.Fatalf("outer-input cut lost its prefix guard: %x", encoded.Bytes())
		}
	}
}
