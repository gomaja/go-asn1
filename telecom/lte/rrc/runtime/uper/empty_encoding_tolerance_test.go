// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/empty_encoding_tolerance_test.go; SHA-256 66142c75b0e256e6a0cc985b81e09252cc040806344fa37326747055afeefd65.
package uper

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func toleranceOption(t *testing.T, name string, log *ToleranceLog) DecodeOptions {
	t.Helper()
	var options DecodeOptions
	field := reflect.ValueOf(&options).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("DecodeOptions.%s is missing", name)
	}
	field.Set(reflect.ValueOf(log))
	return options
}

// X.691 (02/2021) §11.1.3.1 replaces an empty encoding with one zero
// octet. Accepting a nonzero replacement is an explicit receiver choice.
func TestEmptyEncodingNonzeroOctetTolerance(t *testing.T) {
	for _, open := range []bool{false, true} {
		for value := 0; value <= 255; value++ {
			wire := []byte{byte(value)}
			var log ToleranceLog
			bb := NewBitBufferFromBytes(wire)
			if err := bb.SetDecodeOptions(toleranceOption(t, "EmptyEncodingTolerance", &log)); err != nil {
				t.Fatal(err)
			}
			var final FinalPadding
			if open {
				padding, err := CaptureOpenTypePadding(bb)
				if err != nil {
					t.Fatal(err)
				}
				final = finalPaddingOf(padding)
				bb.commitRecords("Empty")
			} else {
				var err error
				final, err = CaptureFinalBits(bb, "Empty")
				if err != nil {
					t.Fatalf("%02x: %v", value, err)
				}
			}
			records := log.Snapshot()
			if value == 0 {
				if len(records) != 0 {
					t.Fatal("canonical empty encoding recorded")
				}
			} else {
				if len(records) != 1 || records[0].Path != "Empty" || records[0].Kind.String() != "nonzero empty encoding" || records[0].Offset != 0 || records[0].Bits.BitLength != 8 || !bytes.Equal(records[0].Bits.Bytes, wire) {
					t.Fatalf("%02x records=%+v", value, records)
				}
			}
			encoded, err := NewBitBuffer().CompleteBytesWithFinalPadding(final)
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("%02x replay=%x err=%v", value, encoded, err)
			}
		}
	}
	for _, options := range []DecodeOptions{{}, {TrailingBitsTolerance: &ToleranceLog{}, TruncatedExtensionTolerance: &ToleranceLog{}, ExtensionRecoveryTolerance: &ToleranceLog{}}} {
		bb := NewBitBufferFromBytes([]byte{0x80})
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureFinalBits(bb, "Empty"); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("old option accepted nonzero empty encoding: %v", err)
		}
	}
}

func TestEmptyEncodingToleranceWithTrailingBitsAndFailures(t *testing.T) {
	var log ToleranceLog
	options := toleranceOption(t, "EmptyEncodingTolerance", &log)
	options.TrailingBitsTolerance = &log
	bb := NewBitBufferFromBytes([]byte{0x80, 0x55})
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	final, err := CaptureFinalBits(bb, "Empty")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewBitBuffer().CompleteBytesWithFinalPadding(final)
	if err != nil || !bytes.Equal(replay, []byte{0x80, 0x55}) || len(log.Snapshot()) != 2 {
		t.Fatalf("replay=%x records=%+v err=%v", replay, log.Snapshot(), err)
	}
	log.Reset()
	// The option does not allow a zero-bit BIT STRING encoding to use a 1 bit.
	bb, _ = NewBitBufferFromBits([]byte{0x80}, 1)
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedBits(bb); !errors.Is(err, ErrInvalidValue) || len(log.Snapshot()) != 0 {
		t.Fatalf("bit encoding accepted: %v", err)
	}
	// An enabled log stays empty after a failed complete decode.
	bb = NewBitBufferFromBytes(nil)
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Empty"); err == nil || len(log.Snapshot()) != 0 {
		t.Fatal("empty input accepted or logged")
	}
}

func TestEmptyEncodingRecordsKeepPathWithoutPaddingCollector(t *testing.T) {
	for _, choice := range []bool{false, true} {
		var log ToleranceLog
		parent := NewBitBufferFromBytes([]byte{0})
		if err := parent.SetDecodeOptions(toleranceOption(t, "EmptyEncodingTolerance", &log)); err != nil {
			t.Fatal(err)
		}
		mark := parent.PaddingComponent("Values")
		index := parent.PaddingIndex(1)
		recovery := parent.RecoveryComponent("Nested")
		recoveryIndex := parent.RecoveryIndex(2)
		child := NewNestedDecodeBuffer([]byte{0x80}, parent)
		var err error
		if choice {
			_, err = CaptureChoicePadding(child, "Selected")
		} else {
			_, err = CaptureExtensionPadding(child, 2, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		parent.LeaveComponent(recoveryIndex)
		parent.LeaveComponent(recovery)
		parent.LeaveComponent(index)
		parent.LeaveComponent(mark)
		if _, err := parent.ReadBit(); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureFinalBits(parent, "Root"); err != nil {
			t.Fatal(err)
		}
		expected := "Root.Values[1].Nested[2].ExtData_[2]"
		if choice {
			expected = "Root.Values[1].Nested[2].Selected"
		}
		records := log.Snapshot()
		if len(records) != 1 || records[0].Path != expected {
			t.Fatalf("records=%+v want path %s", records, expected)
		}
	}
}
