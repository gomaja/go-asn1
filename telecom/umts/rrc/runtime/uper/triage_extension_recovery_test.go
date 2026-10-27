// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/triage_extension_recovery_test.go; SHA-256 204925137ecc472e638b4c7bfe35d6f8551294cb4f279aca44ca0abb31ab5489.
package uper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// Recovery applies only after DecodeOpenType has bounded a known addition
// (X.691 (02/2021) 11.2.1–11.2.2, 19.9). The caller commits its candidate
// only when DecodeKnown reports a complete value.
func TestKnownExtensionRecovery(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		t.Run(fmt.Sprint(aligned), func(t *testing.T) {
			var log ToleranceLog
			parent := NewBitBufferFromBytes([]byte{0xaa})
			if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
				t.Fatal(err)
			}
			mark := parent.EnterComponent("Holder")
			a := ExtensionAdditions{aligned: aligned, present: []bool{true, true}}
			decoded, padding, err := decodeKnownAddition(&a, parent, 0, []byte{0x80}, func(child *BitBuffer) error {
				if _, err := child.ReadBits(3); err != nil {
					return err
				}
				child.recordTolerance(ToleratedTrailingBits, 0, TrailingBits{Bytes: []byte{0}, BitLength: 1})
				child.trace.deferred = append(child.trace.deferred, pendingDeferral{})
				child.EnterComponent("Abandoned")
				return fmt.Errorf("leaf: %w", ErrTruncated)
			})
			if err != nil || decoded || !padding.IsZero() || a.present[0] || !a.present[1] || !a.Recovered() {
				t.Fatalf("decode=%v padding=%v err=%v bitmap=%v", decoded, padding, err, a.present)
			}
			if len(log.Snapshot()) != 0 {
				t.Fatal("published before top-level success")
			}
			if len(parent.trace.deferred) != 0 {
				t.Fatal("partial group published a deferral")
			}
			if len(parent.trace.pending) != 1 {
				t.Fatalf("partial group's records survived: %+v", parent.trace.pending)
			}
			parent.LeaveComponent(mark)
			parent.commitRecords("Outer")
			records := log.Snapshot()
			if len(records) != 1 {
				t.Fatalf("records=%+v", records)
			}
			r := records[0]
			if r.Path != "Outer.Holder.ExtData_[0]" || r.Kind != ToleratedIncompleteExtension || r.DeclaredLength != 1 || r.ConsumedBits != 3 || !errors.Is(r.Err, ErrTruncated) || r.Bits.BitLength != 8 || !bytes.Equal(r.Bits.Bytes, []byte{0x80}) {
				t.Fatalf("record=%+v", r)
			}
			records[0].Bits.Bytes[0] = 0
			if log.Snapshot()[0].Bits.Bytes[0] != 0x80 {
				t.Fatal("snapshot aliases provenance")
			}
			decoded, _, err = decodeKnownAddition(&a, parent, 1, []byte{0x80}, func(child *BitBuffer) error { _, err := child.ReadBits(1); return err })
			if err != nil || !decoded {
				t.Fatalf("later addition=%v %v", decoded, err)
			}
		})
	}
}

func TestKnownExtensionRecoveryPredicate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		recover bool
	}{
		{"truncated", ErrTruncated, true}, {"wrapped", fmt.Errorf("nested: %w", ErrTruncated), true},
		{"invalid", ErrInvalidValue, false}, {"extra", ErrExtraData, false}, {"limit", ErrResourceLimit, false},
		{"constraint", ErrConstraintViolation, false}, {"joined", errors.Join(ErrInvalidValue, ErrTruncated), false},
		{"multiple", fmt.Errorf("%w: %w", ErrTruncated, ErrResourceLimit), false}, {"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				parent := NewBitBufferFromBytes([]byte{0})
				if enabled {
					if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
						t.Fatal(err)
					}
				}
				a := ExtensionAdditions{present: []bool{true}}
				decoded, _, err := decodeKnownAddition(&a, parent, 0, []byte{0}, func(*BitBuffer) error { return tc.err })
				want := enabled && tc.recover
				if tc.err == nil {
					if err != nil || !decoded {
						t.Fatalf("success=%v %v", decoded, err)
					}
					continue
				}
				if want {
					if err != nil || decoded || a.present[0] {
						t.Fatalf("recover=%v %v %v", decoded, err, a.present)
					}
				} else if err != tc.err || decoded || !a.present[0] {
					t.Fatalf("rejected=%v %v %v", decoded, err, a.present)
				}
			}
		})
	}
	// Truncation while checking padding is structural, rather than a failed
	// known value. A zero-bit complete encoding needs a zero octet (§11.1.4).
	parent := NewBitBufferFromBytes([]byte{0})
	if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	a := ExtensionAdditions{present: []bool{true}}
	if _, _, err := decodeKnownAddition(&a, parent, 0, nil, func(*BitBuffer) error { return nil }); err == nil || a.Recovered() {
		t.Fatalf("padding error recovered: %v", err)
	}
}

func FuzzKnownExtensionRecoveryPredicate(f *testing.F) {
	f.Add([]byte{0x80}, uint8(3), uint8(0))
	f.Add([]byte{}, uint8(9), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, width, kind uint8) {
		if len(data) > 4096 {
			t.Skip()
		}
		parent := NewBitBufferFromBytes(data)
		if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
			t.Fatal(err)
		}
		a := ExtensionAdditions{present: []bool{true}}
		var nested error
		decoded, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
			_, nested = child.ReadBits(int(width) % 65)
			switch kind % 4 {
			case 1:
				nested = ErrInvalidValue
			case 2:
				nested = errors.Join(ErrTruncated, ErrResourceLimit)
			case 3:
				nested = fmt.Errorf("field: %w", nested)
			}
			return nested
		})
		if a.Recovered() {
			if kind%4 == 1 || kind%4 == 2 || !errors.Is(nested, ErrTruncated) || err != nil || decoded {
				t.Fatalf("unsafe recovery: %v %v", nested, err)
			}
		} else if errors.Is(nested, ErrTruncated) && kind%4 != 2 {
			t.Fatalf("bounded truncation rejected: %v", err)
		}
	})
}

func TestKnownRecoveryProvenance(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0xa5})
	if _, err := parent.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	a := ExtensionAdditions{recovered: true}
	expected := NewBitBuffer()
	if err := expected.WriteBits(0x5a, 8); err != nil {
		t.Fatal(err)
	}
	final, err := a.RecordRecovery(parent, expected, ExplicitDefaults(1))
	if err != nil || !final.Recovered() || final.Truncated() || !final.ExplicitDefault(0) {
		t.Fatalf("provenance=%+v %v", final, err)
	}
	merged := finalPaddingOf(CompletePadding{bits: 1, count: 3}).WithRecords(final)
	if !merged.Recovered() || !merged.ExplicitDefault(0) {
		t.Fatal("WithRecords dropped recovery")
	}
	for _, value := range []uint64{0x5a, 0x5b} {
		bb := NewBitBuffer()
		if err := bb.WriteBits(value, 8); err != nil {
			t.Fatal(err)
		}
		AppendExtensionRecovery(bb, merged, 0)
		want := byte(value)
		if value == 0x5a {
			want = 0xa5
		}
		if !bytes.Equal(bb.data, []byte{want}) {
			t.Fatalf("value %x became %x", value, bb.data)
		}
	}
	// Replay bytes are owned by the value, independently of the input.
	parent.data[0] = 0
	bb := NewBitBuffer()
	if err := bb.WriteBits(0x5a, 8); err != nil {
		t.Fatal(err)
	}
	AppendExtensionRecovery(bb, final, 0)
	if !bytes.Equal(bb.data, []byte{0xa5}) {
		t.Fatal("provenance aliases input")
	}
}

func decodeKnownAddition(a *ExtensionAdditions, bb *BitBuffer, index int64, data []byte, decode func(*BitBuffer) error) (bool, CompletePadding, error) {
	child := NewNestedDecodeBuffer(data, bb)
	if err := child.EnterOpenType(); err != nil {
		return false, CompletePadding{}, err
	}
	checkpoint := child.CheckpointKnownAddition()
	return a.CompleteKnownAddition(child, index, data, checkpoint, decode(child), true)
}

// A recovered addition's record locates its open type where Received
// admitted it: the first bit of the length determinant, in the encoding that
// carries the extended value (go-asn1#235). Inside a bounded open type that
// is the nested buffer's own position. The value's first addition decodes;
// the second one's known value needs nine bits of its one content octet.
func TestKnownExtensionRecoveryOffset(t *testing.T) {
	extended := func(lead int) []byte {
		w := NewBitBuffer()
		if err := w.WriteBits(1, lead); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := EncodeOpenType(w, []byte{0x80}); err != nil {
				t.Fatal(err)
			}
		}
		return w.CompleteBytes()
	}
	// read follows the generated decoder: Received, the open type, then the
	// known value in its own buffer.
	read := func(a *ExtensionAdditions, bb *BitBuffer, index int64, decode func(*BitBuffer) error) (bool, error) {
		if !a.Received(bb, index) {
			return false, fmt.Errorf("addition %d not received", index)
		}
		data, err := DecodeOpenType(bb)
		if err != nil {
			return false, err
		}
		child := NewNestedDecodeBuffer(data, bb)
		if err := child.EnterOpenType(); err != nil {
			return false, err
		}
		checkpoint := child.CheckpointKnownAddition()
		decoded, _, err := a.CompleteKnownAddition(child, index, data, checkpoint, decode(child), false)
		return decoded, err
	}
	for _, tc := range []struct {
		name         string
		cut          bool
		prefix, lead int
	}{
		{"top-level", false, 0, 5}, {"top-level with cut tolerance", true, 0, 5}, {"nested", false, 3, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log, cutLog ToleranceLog
			options := DecodeOptions{ExtensionRecoveryTolerance: &log}
			if tc.cut {
				options.TruncatedExtensionTolerance = &cutLog
			}
			input := extended(tc.lead)
			if tc.prefix != 0 {
				w := NewBitBuffer()
				if err := w.WriteBits(0, tc.prefix); err != nil {
					t.Fatal(err)
				}
				if err := EncodeOpenType(w, input); err != nil {
					t.Fatal(err)
				}
				input = w.CompleteBytes()
			}
			top := NewBitBufferFromBytes(input)
			if err := top.SetDecodeOptions(options); err != nil {
				t.Fatal(err)
			}
			bb := top
			if tc.prefix != 0 {
				if _, err := top.ReadBits(tc.prefix); err != nil {
					t.Fatal(err)
				}
				data, err := DecodeOpenType(top)
				if err != nil {
					t.Fatal(err)
				}
				bb = NewNestedDecodeBuffer(data, top)
			}
			if _, err := bb.ReadBits(tc.lead); err != nil {
				t.Fatal(err)
			}
			a := ExtensionAdditions{present: []bool{true, true}}
			if decoded, err := read(&a, bb, 0, func(child *BitBuffer) error { _, err := child.ReadBit(); return err }); err != nil || !decoded {
				t.Fatalf("complete addition=%v %v", decoded, err)
			}
			overrun := func(child *BitBuffer) error {
				if _, err := child.ReadBit(); err != nil {
					return err
				}
				_, err := child.ReadBits(8)
				return err
			}
			if decoded, err := read(&a, bb, 1, overrun); err != nil || decoded || !a.Recovered() {
				t.Fatalf("incomplete addition=%v %v", decoded, err)
			}
			top.commitRecords("Outer")
			records := log.Snapshot()
			if len(records) != 1 || len(cutLog.Snapshot()) != 0 {
				t.Fatalf("records=%+v cut=%+v", records, cutLog.Snapshot())
			}
			// The second open type follows the first one's 8-bit length
			// determinant and content octet (X.691 (02/2021) 11.2.2, 11.9.3.6).
			r := records[0]
			if want := tc.lead + 16; r.Offset != want || r.Path != "Outer.ExtData_[1]" || r.Kind != ToleratedIncompleteExtension || r.DeclaredLength != 1 || r.ConsumedBits != 8 || !errors.Is(r.Err, ErrTruncated) {
				t.Fatalf("record=%+v, want Offset %d", r, want)
			}
		})
	}
}
