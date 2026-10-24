// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/deferral_record_test.go; SHA-256 1b211a418eb4d5d87eeb8051df370fd5b59db889f84ec97551fde1c69fcf084c.
package uper

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// X.691 (02/2021) §11.1.3 distinguishes the exact contained bit length.
// TS 36.331 V19.4.0 §8.1 motivates deferring a failed contained value.
func TestDeferralRecordExposesRetainedValue(t *testing.T) {
	for _, mode := range []ContainedDecoding{DeferAll, DeferOnError} {
		t.Run(mode.String(), func(t *testing.T) {
			var log DeferralLog
			parent := NewBitBufferFromBytes([]byte{0})
			if err := parent.SetDecodeOptions(DecodeOptions{ContainedDecoding: mode, Deferrals: &log}); err != nil {
				t.Fatal(err)
			}
			mark := parent.EnterComponent("Values")
			index := parent.EnterIndex(2)
			site := parent.EnterContained()
			var cause error
			if mode == DeferOnError {
				cause = ErrTruncated
			}
			final := site.DeferBits([]byte{0xa0}, 3, cause)
			parent.LeaveComponent(index)
			parent.LeaveComponent(mark)
			if _, err := parent.ReadBits(1); err != nil {
				t.Fatal(err)
			}
			if _, err := CaptureFinalBits(parent, "Envelope"); err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			if len(records) != 1 {
				t.Fatalf("records=%+v", records)
			}
			field := reflect.ValueOf(records[0]).FieldByName("Deferred")
			if !field.IsValid() {
				t.Fatal("deferral record has no Deferred reference")
			}
			retained, ok := field.Interface().(*Deferred)
			if !ok || retained != final.Deferred() {
				t.Fatal("record does not reference the shell's retained value")
			}
			if records[0].Path != "Envelope.Values[2]" || retained.Kind() != BitStringContainer || retained.BitLength() != 3 || !bytes.Equal(retained.Bytes(), []byte{0xa0}) || retained.Err() != records[0].Err || !errors.Is(retained.Err(), cause) {
				t.Fatalf("inconsistent retained value: %+v", records[0])
			}
			raw := retained.Bytes()
			raw[0] = 0
			records[0].Path = "changed"
			if !bytes.Equal(retained.Bytes(), []byte{0xa0}) || log.Snapshot()[0].Path != "Envelope.Values[2]" {
				t.Fatal("snapshot or bytes aliases mutable state")
			}
			log.Reset()
			if !bytes.Equal(retained.Bytes(), []byte{0xa0}) {
				t.Fatal("reset invalidated retained value")
			}
		})
	}
}
