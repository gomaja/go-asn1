// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/modes_test.go; SHA-256 0205b6a50cc8929686943bbea5122989de01f6de48b5841c8a55c370d5a28cc7.
package aper

import (
	"errors"
	"sync"
	"testing"
)

func TestReceiverModeHasNoWireTolerance(t *testing.T) {
	for _, options := range [][]DecodeOption{nil, {WithReceiverMode()}} {
		bb := NewBitBufferFromBytes([]byte{0xff})
		settings := ApplyDecodeOptions(options...)
		if err := bb.SetDecodeOptionsAligned(settings); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(1); err != nil {
			t.Fatal(err)
		}
		_, err := CaptureFinalBits(bb, "Synthetic")
		report, err := FinishDecode(settings, err)
		if !errors.Is(err, ErrSyntax) || len(report.Deviations) != 1 || report.Deviations[0].Rule.Clause != "§11.1.4" {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	}
}

func TestReportCeilingRefusesRatherThanOmitting(t *testing.T) {
	settings := ApplyDecodeOptions(WithReceiverMode())
	bb := NewBitBufferFromBytes([]byte{1, 0})
	if err := bb.SetDecodeOptionsAligned(settings); err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	for range 1024 {
		if err := raw.Observe(UnknownIE); err != nil {
			t.Fatal(err)
		}
	}
	if err := raw.Observe(UnknownIE); !errors.Is(err, ErrLimit) {
		t.Fatalf("extra observation=%v", err)
	}
	syntax := bb.syntaxError(bb.BitPos(), "§11.1.4", "synthetic padding error", ErrInvalidValue)
	report, err := FinishDecode(settings, syntax)
	if !errors.Is(err, ErrLimit) || len(report.Observations) != 1024 || len(report.Deviations) != 0 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestReceiverOptionsSharedAcrossCalls(t *testing.T) {
	options := []DecodeOption{WithReceiverMode()}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 20 {
				settings := ApplyDecodeOptions(options...)
				bb := NewBitBufferFromBytes([]byte{1, 0})
				if err := bb.SetDecodeOptionsAligned(settings); err != nil {
					t.Error(err)
					return
				}
				raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
				if err != nil {
					t.Error(err)
					return
				}
				if err := raw.WithPath("Synthetic.value").Observe(UnknownIE); err != nil {
					t.Error(err)
					return
				}
				report, err := FinishDecode(settings, nil)
				if err != nil || len(report.Observations) != 1 {
					t.Errorf("report=%+v err=%v", report, err)
					return
				}
				report.Observations[0].Location.Path = "edited"
				next, err := FinishDecode(ApplyDecodeOptions(options...), nil)
				if err != nil || len(next.Observations) != 0 {
					t.Errorf("findings leaked into another call: %+v %v", next, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

func TestCompleteOptionsRejectInvalidLimits(t *testing.T) {
	for _, option := range []DecodeOption{WithLimits(Limits{MaxDepth: ^uint64(0)}), WithLimits(Limits{MaxInputBytes: ^uint64(0)})} {
		for _, options := range [][]DecodeOption{{option}, {WithReceiverMode(), option}} {
			bb := NewBitBufferFromBytes([]byte{0})
			if err := bb.SetDecodeOptionsAligned(ApplyDecodeOptions(options...)); !errors.Is(err, ErrInvalidOptions) || bb.BitPos() != 0 {
				t.Fatalf("err=%v", err)
			}
		}
	}
}
