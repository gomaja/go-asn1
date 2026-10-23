// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/triage_extension_recovery_test.go; SHA-256 4975a698b73e42b81dbd7b5b1b3dddb42ed7515a345de75418615fbb2431c069.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// Recovery applies only after DecodeOpenTypeAligned has bounded a known addition
// (X.691 (02/2021) 11.2.1–11.2.2, 19.9). The caller commits its candidate
// only when DecodeKnown reports a complete value.
func TestKnownExtensionRecovery(t *testing.T) {
	for _, aligned := range []bool{true} {
		t.Run(fmt.Sprint(aligned), func(t *testing.T) {
			var log ToleranceLog
			parent := NewBitBufferFromBytes([]byte{0xaa})
			if err := parent.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
				t.Fatal(err)
			}
			mark := parent.EnterComponent("Holder")
			a := ExtensionAdditions{aligned: aligned, present: []bool{true, true}}
			decoded, padding, err := decodeKnownAddition(&a, parent, 0, []byte{0x80}, func(child *BitBuffer) error {
				if _, err := child.ReadBits(3); err != nil {
					return err
				}
				child.trace.pending = append(child.trace.pending, Tolerance{Kind: ToleratedIncompleteExtension, Bits: TrailingBits{Bytes: []byte{0}, BitLength: 1}})
				child.EnterComponent("Abandoned")
				return fmt.Errorf("leaf: %w", ErrTruncated)
			})
			if err != nil || decoded || !padding.IsZero() || a.present[0] || !a.present[1] || !a.Recovered() {
				t.Fatalf("decode=%v padding=%v err=%v bitmap=%v", decoded, padding, err, a.present)
			}
			if len(log.Snapshot()) != 0 {
				t.Fatal("published before top-level success")
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
					if err := parent.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
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
	if err := parent.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	a := ExtensionAdditions{present: []bool{true}}
	if _, _, err := decodeKnownAddition(&a, parent, 0, nil, func(*BitBuffer) error { return nil }); err == nil || a.Recovered() {
		t.Fatalf("padding error recovered: %v", err)
	}
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
	final, err := a.RecordRecovery(parent, expected, FinalPadding{})
	if err != nil || !final.Recovered() || final.Truncated() {
		t.Fatalf("provenance=%+v %v", final, err)
	}
	if suffix := final.Trailing(); suffix.BitLength != 0 || len(suffix.Bytes) != 0 {
		t.Fatalf("recovery created a trailing suffix: %+v", suffix)
	}
	merged := finalPaddingOf(CompletePadding{bits: 1, count: 3}).WithRecords(final)
	if !merged.Recovered() {
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
