// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/real_decimal_complexity_test.go; SHA-256 e5b21d3d564df3dea029501872fac709e2d797efaafc18100b9c1d48cd60765e.
package runtime_test

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestNewRealLargeDecimalWithoutTrailingZero(t *testing.T) {
	// A BER decoder supplies a parsed mantissa. Normalization must not
	// convert it back to a million-digit decimal string just to discover
	// that no trailing zero is present.
	mantissa, ok := new(big.Int).SetString(strings.Repeat("7", 1_000_000), 10)
	if !ok {
		t.Fatal("constructing decimal mantissa")
	}
	var value runtime.Real
	var err error
	allocated, allocations := allocationCost(t, 5, func() { value, err = runtime.NewReal(10, mantissa, big.NewInt(0)) })
	if err != nil || value.Mantissa.Cmp(mantissa) != 0 || value.Exponent.Sign() != 0 {
		t.Fatalf("NewReal: value=%#v err=%v", value, err)
	}
	// Normalization copies binary words; decimal text conversion and reparsing
	// require substantially more storage, even with no trailing zero to remove.
	limit := uint64(8*len(mantissa.Bits())*(strconv.IntSize/8) + 4096)
	if allocated > limit || allocations > 32 {
		t.Fatalf("normalization: %d bytes, %d allocations; want <= %d bytes, 32 allocations", allocated, allocations, limit)
	}
	t.Logf("normalization: %d bytes, %d allocations (limit %d)", allocated, allocations, limit)
}

func TestNewRealLargeDecimalWithOneTrailingZero(t *testing.T) {
	mantissa, ok := new(big.Int).SetString(strings.Repeat("7", 1_000_000)+"0", 10)
	if !ok {
		t.Fatal("constructing decimal mantissa")
	}
	var value runtime.Real
	var err error
	allocated, allocations := allocationCost(t, 5, func() { value, err = runtime.NewReal(10, mantissa, big.NewInt(0)) })
	if err != nil || value.Exponent.Cmp(big.NewInt(1)) != 0 || new(big.Int).Mul(value.Mantissa, big.NewInt(10)).Cmp(mantissa) != 0 {
		t.Fatalf("NewReal: exponent=%v err=%v", value.Exponent, err)
	}
	// Normalization copies binary words; decimal text conversion and reparsing
	// require substantially more storage, even with no trailing zero to remove.
	limit := uint64(8*len(mantissa.Bits())*(strconv.IntSize/8) + 4096)
	if allocated > limit || allocations > 32 {
		t.Fatalf("normalization: %d bytes, %d allocations; want <= %d bytes, 32 allocations", allocated, allocations, limit)
	}
	t.Logf("normalization: %d bytes, %d allocations (limit %d)", allocated, allocations, limit)
}

func TestNewRealDecimalTrailingZeroBatches(t *testing.T) {
	for _, zeros := range []int64{0, 1, 2, 3, 15, 16, 17, 1023, 1024, 1025, 100_000} {
		for _, sign := range []int64{-1, 1} {
			mantissa := new(big.Int).Mul(big.NewInt(37*sign), new(big.Int).Exp(big.NewInt(10), big.NewInt(zeros), nil))
			original := new(big.Int).Set(mantissa)
			got, err := runtime.NewReal(10, mantissa, big.NewInt(-5))
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
