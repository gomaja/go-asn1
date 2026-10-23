// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/recovery_cost_test.go; SHA-256 49d142f4854f8b60fe0e70b04b364a3fe5a65aec2978d24ae9d4ac28cc358692.
package uper

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// Copying the shared parent prefix into every recovered list element makes
// both retained provenance and allocations quadratic in the element count.
func TestRecoveryProvenanceLinearCost(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		for _, count := range []int{1024, 4096, 16384} {
			t.Run(fmt.Sprintf("aligned=%v/count=%d", aligned, count), func(t *testing.T) {
				input := bytes.Repeat([]byte{0xa5, 0x5a}, count)
				parent := NewBitBufferFromBytes(input)
				values := make([]FinalPadding, count)
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				retained := 0
				for i := range values {
					a := BeginExtensionAdditions(parent)
					a.aligned, a.recovered = aligned, true
					if _, err := parent.ReadBits(16); err != nil {
						t.Fatal(err)
					}
					expected, err := a.RecoveryEncoder(parent)
					if err != nil {
						t.Fatal(err)
					}
					if err := expected.WriteBits(0x55, 8); err != nil {
						t.Fatal(err)
					}
					values[i], err = a.RecordRecovery(parent, expected, FinalPadding{})
					if err != nil {
						t.Fatal(err)
					}
					kept := values[i].bits.truncated
					retained += len(kept.input) + len(kept.expected)
				}
				runtime.ReadMemStats(&after)
				allocated := after.TotalAlloc - before.TotalAlloc
				allocations := after.Mallocs - before.Mallocs
				t.Logf("elements=%d retained=%d allocated=%d allocations=%d", count, retained, allocated, allocations)
				if retained > 4*count || allocated > uint64(1024*count+1<<20) || allocations > uint64(16*count+1024) {
					t.Fatalf("recovery cost exceeds linear bound: retained=%d allocated=%d allocations=%d", retained, allocated, allocations)
				}
				encoded := NewBitBuffer()
				for _, final := range values {
					start := encoded.BitsWritten()
					if err := encoded.WriteBits(0x55, 8); err != nil {
						t.Fatal(err)
					}
					AppendExtensionRecovery(encoded, final, start)
				}
				if !bytes.Equal(encoded.Bytes(), input) {
					t.Fatal("unchanged list did not replay exactly")
				}
			})
		}
	}
}

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
