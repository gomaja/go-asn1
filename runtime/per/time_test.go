package per

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// The independent pycrate 0.7.11 UTCTime oracle encodes 2026-09-27
// 11:45:30 UTC as these two wires. X.691 (02/2021) 10.6.5 applies
// X.680 (02/2021) 47.3 and X.690 (02/2021) 11.8.1-11.8.2.
func TestUTCTimePERPycrateOracle(t *testing.T) {
	want := time.Date(2026, 9, 27, 11, 45, 30, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		wire   string
		encode func(*BitBuffer, time.Time) error
		decode func(*BitBuffer) (time.Time, error)
	}{
		{"uper", "0d64d983964dd8b168d59b0b40", EncodeUTCTime, DecodeUTCTime},
		{"aper", "0d3236303932373131343533305a", EncodeUTCTimeAligned, DecodeUTCTimeAligned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oracle, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			bb := NewBitBuffer()
			if err := tc.encode(bb, want); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.CompleteBytes(), oracle) {
				t.Fatalf("wire = %x, want %x", bb.CompleteBytes(), oracle)
			}
			got, err := tc.decode(NewBitBufferFromBytes(oracle))
			if err != nil || !got.Equal(want) {
				t.Fatalf("decode = %s, %v", got, err)
			}
			if _, err := tc.decode(NewBitBufferFromBytes(oracle[:len(oracle)-1])); err == nil {
				t.Fatal("truncated UTCTime accepted")
			}
		})
	}
}

func TestUTCTimePERRejectsUnrepresentableTime(t *testing.T) {
	for _, value := range []time.Time{
		time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 27, 11, 45, 30, 1, time.UTC),
	} {
		if err := EncodeUTCTime(NewBitBuffer(), value); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}
