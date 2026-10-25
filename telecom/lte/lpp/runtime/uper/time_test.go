// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/time_test.go; SHA-256 c1f09f98c797ac8f2563eed65eef91ec5216ff58fe8f493cfb6da8bcf5e3b2a8.
package uper

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/lpp/runtime"
)

func mustUTCTime(t testing.TB, s string) runtime.UTCTime {
	t.Helper()
	value, err := runtime.ParseUTCTime(s)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

var perUTCTimeCodecs = []struct {
	name   string
	wire   string
	encode func(*BitBuffer, runtime.UTCTime) error
	decode func(*BitBuffer) (runtime.UTCTime, error)
}{
	{"uper", "0d64d983964dd8b168d59b0b40", EncodeUTCTime, DecodeUTCTime},
}

// The independent pycrate 0.7.11 UTCTime oracle encodes 2026-09-27
// 11:45:30 UTC ("260927114530Z") as these two wires. X.691 (02/2021) 10.6.5
// applies X.680 (02/2021) 47.3 and X.690 (02/2021) 11.8.1-11.8.2, so
// every input that denotes this instant encodes the same wire.
func TestUTCTimePERPycrateOracle(t *testing.T) {
	want := mustUTCTime(t, "260927114530Z")
	for _, tc := range perUTCTimeCodecs {
		t.Run(tc.name, func(t *testing.T) {
			oracle, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []string{"260927114530Z", "260927124530+0100", "260927064530-0500", "260927114530-0000"} {
				bb := NewBitBuffer()
				if err := tc.encode(bb, mustUTCTime(t, input)); err != nil {
					t.Fatal(input, err)
				}
				if !bytes.Equal(bb.CompleteBytes(), oracle) {
					t.Fatalf("%s: wire = %x, want %x", input, bb.CompleteBytes(), oracle)
				}
			}
			got, err := tc.decode(NewBitBufferFromBytes(oracle))
			if err != nil || got != want {
				t.Fatalf("decode = %s, %v", got, err)
			}
			if _, err := tc.decode(NewBitBufferFromBytes(oracle[:len(oracle)-1])); err == nil {
				t.Fatal("truncated UTCTime accepted")
			}
		})
	}
}

func TestUTCTimePERRejectsUnrepresentableTime(t *testing.T) {
	for _, tc := range perUTCTimeCodecs {
		for _, value := range []runtime.UTCTime{
			mustUTCTime(t, "491231230000-0100"), // 2050-01-01 in UTC
			mustUTCTime(t, "500101003000+0100"), // 1949-12-31 in UTC
			{},
		} {
			err := tc.encode(NewBitBuffer(), value)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("%s: accepted %q: %v", tc.name, value, err)
			}
			if value.IsZero() != errors.Is(err, runtime.ErrTimeNotSet) || !value.IsZero() && !errors.Is(err, runtime.ErrNoCanonicalTime) {
				t.Fatalf("%s: %q: %v", tc.name, value, err)
			}
		}
	}
}

// X.691 (02/2021) §10.6.5 admits only the X.690 (02/2021) §11.8 form, so a
// received noncanonical UTCTime is rejected.

// FuzzPERUTCTimeDecode checks that any accepted wire holds a canonical
// value and that re-encoding it reproduces the consumed bits exactly.
