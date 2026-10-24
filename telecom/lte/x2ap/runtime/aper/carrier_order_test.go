// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/carrier_order_test.go; SHA-256 e2a1bc44a0f3a9d9e0f9b220b1ad93be48ca058148c1b307a0a8ea756a912449.
package aper

import (
	"errors"
	"testing"
)

// X.691 (02/2021) §§11.3.6, 11.4.6, 11.7.4 and 11.8.3 require
// minimal contents before a finite Go carrier can be considered.
func TestIntegerWireRulesBeforeCarrier(t *testing.T) {
	for _, receiver := range []bool{false, true} {
		for _, decoder := range []struct {
			name, clause string
			decode       func(*BitBuffer) (int64, error)
		}{
			{"uint64", "§11.4.6", func(bb *BitBuffer) (int64, error) { _, err := decodeUnconstrainedUint64(bb); return 0, err }},
			{"int64", "§11.4.6", DecodeUnconstrainedWholeNumberAligned},
			{"semi", "§11.7.4", func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) }},
		} {
			for _, tc := range []struct {
				name    string
				content []byte
				want    error
			}{
				{"minimal-ten", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ErrLimit},
				{"nonminimal-ten", make([]byte, 10), ErrSyntax},
				{"redundant-negative-ten", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ErrSyntax},
				{"nonminimal-nine", make([]byte, 9), ErrSyntax},
				{"truncated-ten", nil, ErrTruncated},
			} {
				t.Run(decoder.name+"/"+tc.name+map[bool]string{false: "/strict", true: "/receiver"}[receiver], func(t *testing.T) {
					if decoder.name == "semi" && tc.name == "redundant-negative-ten" {
						tc.want = ErrLimit
					}
					wire := append([]byte{10}, tc.content...)
					if tc.name == "nonminimal-nine" {
						wire[0] = 9
					}
					options := []DecodeOption{}
					if receiver {
						options = append(options, WithReceiverMode())
					}
					state := ApplyDecodeOptions(options...)
					bb := NewBitBufferFromBytes(wire)
					if err := bb.SetDecodeOptionsAligned(state); err != nil {
						t.Fatal(err)
					}
					_, failure := decoder.decode(bb)
					report, err := FinishDecode(state, failure)
					if !errors.Is(err, tc.want) {
						t.Fatalf("got %v, want %v", err, tc.want)
					}
					var located *DecodeError
					if !errors.As(err, &located) || !located.Location.HasWireLocation {
						t.Fatalf("unlocated error: %v", err)
					}
					if tc.want == ErrSyntax {
						if errors.Is(err, ErrLimit) || located.Rule.Clause != decoder.clause || len(report.Deviations) != 1 {
							t.Fatalf("syntax report=%+v err=%+v", report, located)
						}
					} else if tc.want == ErrLimit && len(report.Deviations) != 0 {
						t.Fatalf("operational/truncated report=%+v", report)
					}
				})
			}
		}
	}
}

func TestSemiConstrainedOffsetCarrierIsOperational(t *testing.T) {
	// Minimal unsigned 2^63 is valid above the lower bound but exceeds int64.
	wire := []byte{8, 0x80, 0, 0, 0, 0, 0, 0, 0}
	_, err := DecodeSemiConstrainedWholeNumberAligned(NewBitBufferFromBytes(wire), 0)
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrSyntax) {
		t.Fatalf("carrier overflow: %v", err)
	}
}

func TestIntegerCarrierReadsAreBudgeted(t *testing.T) {
	for _, decode := range []func(*BitBuffer) (int64, error){
		func(bb *BitBuffer) (int64, error) { _, err := decodeUnconstrainedUint64(bb); return 0, err },
		func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) },
	} {
		state := ApplyDecodeOptions()
		bb := NewBitBufferFromBytes([]byte{10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		before := bb.Budget().allocated
		_, err := decode(bb)
		if !errors.Is(err, ErrLimit) || bb.BitPos() != 88 || bb.Budget().allocated < before+10 {
			t.Fatalf("read not charged: pos=%d allocated=%d before=%d err=%v", bb.BitPos(), bb.Budget().allocated, before, err)
		}
	}
}

func TestFragmentedIntegerWireRulesBeforeCarrier(t *testing.T) {
	for _, decode := range []func(*BitBuffer) (int64, error){
		func(bb *BitBuffer) (int64, error) { _, err := decodeUnconstrainedUint64(bb); return 0, err },
		func(bb *BitBuffer) (int64, error) { return DecodeSemiConstrainedWholeNumberAligned(bb, 0) },
	} {
		for _, minimal := range []bool{false, true} {
			contents := make([]byte, 16385)
			if minimal {
				contents[0] = 1
			}
			wire := NewBitBuffer()
			if err := encodeLengthDelimitedOctets(wire, contents, true); err != nil {
				t.Fatal(err)
			}
			_, err := decode(NewBitBufferFromBytes(wire.CompleteBytes()))
			want := ErrSyntax
			if minimal {
				want = ErrLimit
			}
			if !errors.Is(err, want) || minimal && errors.Is(err, ErrSyntax) {
				t.Fatalf("minimal=%v got %v want %v", minimal, err, want)
			}
		}
	}
}
