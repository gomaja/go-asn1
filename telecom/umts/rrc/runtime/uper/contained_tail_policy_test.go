// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/contained_tail_policy_test.go; SHA-256 861bc03e23be43e4afeef21bb8b658efd3df9fa235b7aa3bb32d5dfc7a58e2af.
package uper

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func containedPolicyOption(t *testing.T, log *ToleranceLog, maxBits int, zeroOnly bool) DecodeOptions {
	t.Helper()
	var options DecodeOptions
	field := reflect.ValueOf(&options).Elem().FieldByName("ContainedBitsTolerance")
	if !field.IsValid() {
		t.Fatal("DecodeOptions.ContainedBitsTolerance is missing")
	}
	policy := reflect.New(field.Type().Elem())
	policy.Elem().FieldByName("Log").Set(reflect.ValueOf(log))
	policy.Elem().FieldByName("MaxBits").SetInt(int64(maxBits))
	policy.Elem().FieldByName("ZeroOnly").SetBool(zeroOnly)
	field.Set(policy)
	return options
}

// TS 25.331 V19.0.1 §12.1.3 concerns the outer PDU's extension and
// padding parts. It does not relax X.691 (02/2021) §11.1.3.2 inside BIT STRINGs.
func TestOuterToleranceDoesNotAcceptContainedTail(t *testing.T) {
	var log ToleranceLog
	bb, _ := NewBitBufferFromBits([]byte{0}, 8)
	if err := bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(2); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedBits(bb); !errors.Is(err, ErrExtraData) {
		t.Fatalf("outer tolerance accepted contained tail: %v", err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("failed contained decode logged")
	}
}

func TestContainedTailPolicyBoundsAndReplay(t *testing.T) {
	for _, width := range []int{0, 1, 6, 7, 8, 10} {
		for _, nonzero := range []bool{false, true} {
			for _, bounded := range []bool{false, true} {
				wire := NewBitBuffer()
				_ = wire.WriteBits(0, 2)
				for i := 0; i < width; i++ {
					bit := uint8(0)
					if nonzero && i == 0 {
						bit = 1
					}
					if err := wire.WriteBit(bit); err != nil {
						t.Fatal(err)
					}
				}
				bb, err := NewBitBufferFromBits(wire.Bytes(), 2+width)
				if err != nil {
					t.Fatal(err)
				}
				var log ToleranceLog
				maxBits := 0
				if bounded {
					maxBits = 7
				}
				if err := bb.SetDecodeOptions(containedPolicyOption(t, &log, maxBits, bounded)); err != nil {
					t.Fatal(err)
				}
				if _, err := bb.ReadBits(2); err != nil {
					t.Fatal(err)
				}
				final, err := CaptureDeferredBits(bb, "Contained")
				accepted := !bounded || width <= 7 && (!nonzero || width == 0)
				if !accepted {
					if !errors.Is(err, ErrExtraData) || len(log.Snapshot()) != 0 {
						t.Fatalf("width=%d nonzero=%t accepted/logged: %v", width, nonzero, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				out := NewBitBuffer()
				_ = out.WriteBits(0, 2)
				if err := AppendContainedBits(out, final); err != nil || !bytes.Equal(out.Bytes(), wire.Bytes()) || out.BitPos() != 2+width {
					t.Fatalf("replay=%x/%d err=%v", out.Bytes(), out.BitPos(), err)
				}
				expected := 0
				if width != 0 {
					expected = 1
				}
				if len(log.Snapshot()) != expected {
					t.Fatalf("records=%+v width=%d", log.Snapshot(), width)
				}
			}
		}
	}
}

func TestContainedOctetTailHasSeparatePolicy(t *testing.T) {
	var outer, inner ToleranceLog
	options := containedPolicyOption(t, &inner, 0, false)
	options.TrailingBitsTolerance = &outer
	bb := NewBitBufferFromBytes([]byte{0x05, 0xff})
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	final, err := CaptureContainedFinalBits(bb)
	if err != nil {
		t.Fatal(err)
	}
	bb.commitRecords("Octets")
	if len(inner.Snapshot()) != 1 || len(outer.Snapshot()) != 0 {
		t.Fatalf("inner=%+v outer=%+v", inner.Snapshot(), outer.Snapshot())
	}
	out := NewBitBuffer()
	_ = out.WriteBits(0, 3)
	replay, err := out.CompleteBytesWithFinalPadding(final)
	if err != nil || !bytes.Equal(replay, []byte{5, 255}) {
		t.Fatalf("replay=%x err=%v", replay, err)
	}
}

func TestContainedTailPolicyRejectsInvalidOptions(t *testing.T) {
	for _, policy := range []*ContainedBitsPolicy{{}, {Log: &ToleranceLog{}, MaxBits: -1}} {
		options := DecodeOptions{ContainedBitsTolerance: policy}
		if err := ValidateDecodeOptions(options); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("invalid options accepted: %v", err)
		}
		if err := NewBitBufferFromBytes([]byte{0}).SetDecodeOptions(options); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("invalid options initialized: %v", err)
		}
	}
}
