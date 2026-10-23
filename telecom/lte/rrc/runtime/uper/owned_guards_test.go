// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/owned_guards_test.go; SHA-256 5b86423eba93c68422cf4733f44da48c1527d7ed8044c0560e4db587bd4dd3d4.
package uper

import (
	"errors"
	"math/big"
	"testing"
)

// X.691 (02/2021) §§11.7 and 13: a semi-constrained INTEGER carries a
// non-negative minimal offset from its lower bound, in at least one octet.
func TestBigSemiConstrainedBoundsAndMalformedOffsets(t *testing.T) {
	lower := int64(10)
	for _, value := range []int64{9, 10, 11} {
		writer := NewBitBuffer()
		err := EncodeIntegerBig(writer, big.NewInt(value), &lower, nil, false)
		if value < lower {
			if !errors.Is(err, ErrConstraintViolation) || writer.BitsWritten() != 0 {
				t.Fatalf("below bound: bits=%d err=%v", writer.BitsWritten(), err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeIntegerBig(NewBitBufferFromBytes(writer.Bytes()), &lower, nil, false)
		if err != nil || got.Cmp(big.NewInt(value)) != 0 {
			t.Fatalf("offset decode: %v %v", got, err)
		}
	}
	for _, wire := range [][]byte{{1}, {2, 0, 1}, {0}} {
		if _, err := DecodeIntegerBig(NewBitBufferFromBytes(wire), &lower, nil, false); err == nil {
			t.Fatalf("malformed offset accepted: %x", wire)
		}
	}
}

// X.691 (02/2021) §11.1.3.2 requires one zero bit for an empty value in a
// BIT STRING. Keep read failures distinct from missing or nonzero bits.
func TestEmptyContainedBitEncodingAndFailures(t *testing.T) {
	empty := NewBitBuffer()
	if err := AppendContainedBits(empty, FinalPadding{}); err != nil || empty.BitsWritten() != 1 || len(empty.Bytes()) != 1 || empty.Bytes()[0] != 0 {
		t.Fatalf("empty encoding: %x/%d %v", empty.Bytes(), empty.BitsWritten(), err)
	}
	for _, fixture := range []struct {
		name   string
		reader *BitBuffer
		want   error
	}{
		{"valid zero", &BitBuffer{data: []byte{0}, bitLen: 1}, nil},
		{"missing bit", &BitBuffer{}, ErrInvalidValue},
		{"nonzero bit", &BitBuffer{data: []byte{0x80}, bitLen: 1}, ErrInvalidValue},
		{"invalid input length", &BitBuffer{data: []byte{0}, bitLen: 1, invalidLength: true}, ErrInvalidValue},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			kept, err := CaptureContainedBits(fixture.reader)
			if !errors.Is(err, fixture.want) {
				t.Fatalf("capture: %v, want %v", err, fixture.want)
			}
			if fixture.want == nil && (!kept.IsZero() || fixture.reader.BitsRemaining() != 0) {
				t.Fatalf("empty value retained padding or unread bits: %+v", kept)
			}
		})
	}
}

func TestEmptyContainedValueReplaysItsToleratedSuffix(t *testing.T) {
	reader, err := NewBitBufferFromBits([]byte{0x40}, 2)
	if err != nil {
		t.Fatal(err)
	}
	var log ToleranceLog
	if err := reader.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	kept, err := CaptureContainedBits(reader)
	if err != nil {
		t.Fatal(err)
	}
	writer := NewBitBuffer()
	if err := AppendContainedBits(writer, kept); err != nil || writer.BitsWritten() != 2 || len(writer.Bytes()) != 1 || writer.Bytes()[0] != 0x40 {
		t.Fatalf("empty value with suffix replay: %x/%d %v", writer.Bytes(), writer.BitsWritten(), err)
	}
	reader.commitRecords("Empty")
	if len(log.Snapshot()) != 1 {
		t.Fatalf("suffix records: %d", len(log.Snapshot()))
	}
}
