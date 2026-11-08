// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/time_leap_second_test.go; SHA-256 77a921209a5295caa333b70f5530b20151125c500958d1c7cfff3097194966d5.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestBERGeneralizedTimeLeapSecond(t *testing.T) {
	// Synthetic issue vectors; DER keeps second 60 (X.690 (02/2021) §11.7).
	for _, tc := range []struct {
		wire          string
		utc, ber, der bool
	}{
		{"180f32303136313233313233353936305a", false, true, true},
		{"181332303136313233313233353936302e3530305a", false, true, false},
		{"180f32303136313233313233353935395a", false, true, true},
		{"170d3136313233313233353936305a", true, false, false},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(wire); (err == nil) != tc.ber {
			t.Errorf("BER %s: %v", tc.wire, err)
		}
		if err := ValidateDEREncodedElement(wire); (err == nil) != tc.der {
			t.Errorf("DER %s: %v", tc.wire, err)
		}
		if tc.utc {
			if _, _, err := DecodeUTCTime(wire); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("UTC leap second: %v", err)
			}
			continue
		}
		g, n, err := DecodeGeneralizedTime(wire)
		if err != nil || n != len(wire) || g.String() != string(wire[2:]) {
			t.Fatalf("typed decode = %q, %d, %v", g, n, err)
		}
		encoded, err := EncodeGeneralizedTime(g)
		if err != nil || !bytes.Equal(encoded, wire) {
			t.Fatalf("BER re-encode = %x, %v", encoded, err)
		}
	}
	for _, text := range []string{"20161231235960Z", "20161230123460Z", "20161230123460.5Z", "20161230123460", "20161230123460,5", "20170101005960+01", "20161230123460.5-0530"} {
		wire := primitiveTime(tag.TagGeneralizedTime, text)
		for _, input := range [][]byte{wire, append(append([]byte{0x38, byte(len(text) + 4), 4, 13}, text[:13]...), append([]byte{4, byte(len(text) - 13)}, text[13:]...)...)} {
			if err := ValidateBERElement(input); err != nil {
				t.Fatalf("scanner %q: %v", text, err)
			}
			g, n, err := DecodeGeneralizedTime(input)
			if err != nil || n != len(input) || g.String() != text {
				t.Fatalf("typed %q = %q, %d, %v", text, g, n, err)
			}
		}
		g, err := runtime.ParseGeneralizedTime(text)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeGeneralizedTime(g)
		if err != nil || !bytes.Equal(encoded, wire) {
			t.Fatalf("lexical BER %q = %x, %v", text, encoded, err)
		}
		canonical, err := g.Canonical()
		if err == nil {
			encoded, err := EncodeGeneralizedTimeDER(g)
			if err != nil || !bytes.Equal(encoded, primitiveTime(tag.TagGeneralizedTime, canonical.String())) || ValidateDEREncodedElement(encoded) != nil {
				t.Fatalf("DER %q = %x, %v", text, encoded, err)
			}
		}
	}
	for _, tc := range []struct {
		number int
		text   string
	}{{24, "20161231235961Z"}, {24, "20161230123461.5"}, {23, "161231235960Z"}} {
		wire := primitiveTime(tc.number, tc.text)
		if err := ValidateBERElement(wire); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("BER accepted %q: %v", tc.text, err)
		}
		if err := ValidateDEREncodedElement(wire); err == nil {
			t.Errorf("DER accepted %q", tc.text)
		}
	}
}
