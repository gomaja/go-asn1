// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/triage_extension_recovery_test.go; SHA-256 6713059d65fce0f08022cd2ec9b72777e1e252022a38ce22054501dacade43f5.
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
	return a.CompleteKnownAddition(child, index, data, checkpoint, decode(child))
}

func TestExtensionRecoveryEnabled(t *testing.T) {
	var additions ExtensionAdditions
	for _, tc := range []struct {
		name    string
		options DecodeOptions
		want    bool
	}{
		{name: "strict"},
		{name: "trailing", options: DecodeOptions{TrailingBitsTolerance: &ToleranceLog{}}},
		{name: "truncated", options: DecodeOptions{TruncatedExtensionTolerance: &ToleranceLog{}}},
		{name: "recovery", options: DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := NewBitBufferFromBytes([]byte{0})
			if err := parent.SetDecodeOptions(tc.options); err != nil {
				t.Fatal(err)
			}
			if got := additions.RecoveryEnabled(parent); got != tc.want {
				t.Fatalf("RecoveryEnabled = %v, want %v", got, tc.want)
			}
			child := NewNestedDecodeBuffer([]byte{0}, parent)
			if got := additions.RecoveryEnabled(child); got != tc.want {
				t.Fatalf("nested RecoveryEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}
