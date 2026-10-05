package runtime

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNewRealLargeDecimalWithoutTrailingZero(t *testing.T) {
	// A BER decoder supplies a parsed mantissa. Normalization must not
	// convert it back to a million-digit decimal string just to discover
	// that no trailing zero is present.
	mantissa, ok := new(big.Int).SetString(strings.Repeat("7", 1_000_000), 10)
	if !ok {
		t.Fatal("constructing decimal mantissa")
	}
	start := time.Now()
	value, err := NewReal(10, mantissa, big.NewInt(0))
	elapsed := time.Since(start)
	if err != nil || value.Mantissa.Cmp(mantissa) != 0 || value.Exponent.Sign() != 0 {
		t.Fatalf("NewReal: value=%#v err=%v", value, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("NewReal converted a nonzero-ending decimal mantissa in %s", elapsed)
	}
}

func TestNewRealLargeDecimalWithOneTrailingZero(t *testing.T) {
	mantissa, ok := new(big.Int).SetString(strings.Repeat("7", 1_000_000)+"0", 10)
	if !ok {
		t.Fatal("constructing decimal mantissa")
	}
	start := time.Now()
	value, err := NewReal(10, mantissa, big.NewInt(0))
	elapsed := time.Since(start)
	if err != nil || value.Exponent.Cmp(big.NewInt(1)) != 0 || new(big.Int).Mul(value.Mantissa, big.NewInt(10)).Cmp(mantissa) != 0 {
		t.Fatalf("NewReal: exponent=%v err=%v", value.Exponent, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("NewReal used large-factor division for one decimal zero in %s", elapsed)
	}
}

func TestNewRealDecimalTrailingZeroBatches(t *testing.T) {
	for _, zeros := range []int64{0, 1, 2, 3, 15, 16, 17, 1023, 1024, 1025, 100_000} {
		for _, sign := range []int64{-1, 1} {
			mantissa := new(big.Int).Mul(big.NewInt(37*sign), new(big.Int).Exp(big.NewInt(10), big.NewInt(zeros), nil))
			original := new(big.Int).Set(mantissa)
			got, err := NewReal(10, mantissa, big.NewInt(-5))
			if err != nil {
				t.Fatal(err)
			}
			if got.Mantissa.Cmp(big.NewInt(37*sign)) != 0 || got.Exponent.Cmp(big.NewInt(zeros-5)) != 0 {
				t.Fatalf("10^%d sign %d: mantissa=%s exponent=%s", zeros, sign, got.Mantissa, got.Exponent)
			}
			if mantissa.Cmp(original) != 0 {
				t.Fatal("NewReal mutated caller's mantissa")
			}
		}
	}
}
