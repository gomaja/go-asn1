package ber

import (
	"bytes"
	"math/big"
	"testing"
)

// The value-level big-integer codec must agree with the int64 one wherever
// both apply, and must keep working past the 8-octet ceiling that forced it
// into existence.
func TestBigIntValueRoundTrip(t *testing.T) {
	for _, s := range []string{
		"0", "1", "-1", "127", "128", "-128", "-129", "255", "256", "-256",
		"9223372036854775807", "-9223372036854775808",
		// Wider than int64: the 9-octet class that appears on the GSMA
		// SGP.26 CI and EUICC certificates.
		"13907681915072546568",
		"1461501637330902918203684832716283019655932542975",
		"-13907681915072546568",
	} {
		want, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("bad literal %s", s)
		}
		enc := EncodeBigIntValue(want)
		got, err := DecodeBigIntValue(enc)
		if err != nil {
			t.Errorf("%s: decode: %v", s, err)
			continue
		}
		if got.Cmp(want) != 0 {
			t.Errorf("%s: round trip gave %s (contents % x)", s, got, enc)
			continue
		}
		// Re-encoding the decoded value must reproduce the same octets, or a
		// decode/encode cycle would not be byte-exact.
		if again := EncodeBigIntValue(got); !bytes.Equal(enc, again) {
			t.Errorf("%s: re-encode differs: % x vs % x", s, enc, again)
		}
	}

	// Agreement with the int64 path on values both can represent.
	for _, v := range []int64{0, 1, -1, 127, -128, 255, 1 << 40, -(1 << 40)} {
		if a, b := EncodeIntegerValue(v), EncodeBigIntValue(big.NewInt(v)); !bytes.Equal(a, b) {
			t.Errorf("%d: int64 encodes % x, big encodes % x", v, a, b)
		}
	}

	if _, err := DecodeBigIntValue(nil); err == nil {
		t.Error("empty contents accepted")
	}
}
