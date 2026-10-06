package ber

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestDecimalRealFormTrackingMatchesCanonicalEncoding(t *testing.T) {
	for _, contents := range []string{
		"\x031.E+0", "\x03-17.E-2", "\x03123456789.E+0",
		"\x031.E1", "\x03-1.E1", "\x031.E123456789012345678901234567890", "\x031.E-123456789012345678901234567890",
		"\x031.E+1", "\x031.E-1", "\x0310.E+0", "\x0301.E+0",
		"\x03+1.E+0", "\x031.0E+0", "\x031.e+00", "\x031,E+0",
		"\x01+00125", "\x02.1250", "\x03  1.E+0",
	} {
		t.Run(contents, func(t *testing.T) {
			encoded := []byte(contents)
			value, err := decodeRealContents(encoded)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := EncodeRealValue(value)
			if err != nil {
				t.Fatal(err)
			}
			wantPreserve := !bytes.Equal(encoded, canonical)
			wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, encoded)
			if err != nil {
				t.Fatal(err)
			}
			opts := TrackBERForm(nil)
			if _, consumed, err := DecodeReal(wire, opts...); err != nil || consumed != len(wire) {
				t.Fatalf("DecodeReal: consumed=%d err=%v", consumed, err)
			}
			implicitOpts := TrackBERForm(nil)
			if _, err := DecodeRealValue(encoded, implicitOpts...); err != nil {
				t.Fatal(err)
			}
			if BERNeedsPreservation(implicitOpts) != wantPreserve {
				t.Fatal("implicit REAL form tracking disagrees with canonical encoding")
			}
			if got := BERNeedsPreservation(opts); got != wantPreserve {
				t.Fatalf("preserve=%v, want %v", got, wantPreserve)
			}
		})
	}
}

func TestTrackedCanonicalDecimalRealDecodeCost(t *testing.T) {
	// Compare with one mandatory decimal-to-binary conversion. The old path
	// converted the value back to decimal several times and decoded it twice.
	digits := strings.Repeat("7", 1_000_000)
	start := time.Now()
	mantissa, ok := new(big.Int).SetString(digits, 10)
	parseTime := time.Since(start)
	if !ok || mantissa.Sign() == 0 {
		t.Fatal("constructing decimal mantissa")
	}
	contents := append([]byte{3}, []byte(digits+".E+0")...)
	wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
	if err != nil {
		t.Fatal(err)
	}
	opts := TrackBERForm(nil)
	start = time.Now()
	value, consumed, err := DecodeReal(wire, opts...)
	decodeTime := time.Since(start)
	if err != nil || consumed != len(wire) || value.Mantissa.Cmp(mantissa) != 0 || BERNeedsPreservation(opts) {
		t.Fatalf("DecodeReal: consumed=%d preserve=%v err=%v", consumed, BERNeedsPreservation(opts), err)
	}
	if decodeTime > 2*parseTime+500*time.Millisecond {
		t.Fatalf("tracked decimal decode=%s, single SetString=%s", decodeTime, parseTime)
	}
}

func FuzzDecimalRealCanonicalForm(f *testing.F) {
	for _, value := range []string{"\x031.E+0", "\x03-17.E-2", "\x0310.E+0", "\x01+00125", "\x02.1250", "\x031.E12345678901234567890"} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) == 0 || len(contents) > 8192 || contents[0]&0xc0 != 0 {
			return
		}
		decoded, err := decodeRealContents(contents)
		if err != nil {
			return
		}
		canonical, err := EncodeRealValue(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := canonicalDecimalRealContents(contents), bytes.Equal(contents, canonical); got != want {
			t.Fatalf("canonical(%x) = %v, encoder = %x", contents, got, canonical)
		}
		wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDERElement(wire); (err == nil) != bytes.Equal(contents, canonical) {
			t.Fatalf("DER validation = %v; received %x, canonical %x", err, contents, canonical)
		}
	})
}
