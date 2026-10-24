// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/integer_budget_test.go; SHA-256 5ae932a5fb67ecc5b5043652469da2fe0c52966f1f2094d9c553c334879966ef.
package aper

import (
	"errors"
	"math/big"
	"testing"
)

func TestBigIntegerWorkspacesAreBudgetedBeforeOutput(t *testing.T) {
	value := new(big.Int).Lsh(big.NewInt(1), 65535)
	budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: operationMetadataBytes + 32768}))
	if err != nil {
		t.Fatal(err)
	}
	bb := NewBudgetBuffer(budget)
	err = EncodeIntegerBigBoundsAligned(bb, value, nil, nil, false)
	if !errors.Is(err, ErrLimit) || bb.BitPos() != 0 {
		t.Fatalf("workspace allocated before reservation: bit=%d usage=%+v err=%v", bb.BitPos(), bb.Usage(), err)
	}
	writer := NewBitBuffer()
	if err := EncodeIntegerBigBoundsAligned(writer, value, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	state := ApplyDecodeOptions(WithLimits(Limits{MaxAllocatedBytes: operationMetadataBytes + 32768}))
	reader := NewBitBufferFromBytes(writer.CompleteBytes())
	if err := reader.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntegerBigBoundsAligned(reader, nil, nil, false); !errors.Is(err, ErrLimit) {
		t.Fatalf("decoded workspace escaped budget: %+v %v", reader.Usage(), err)
	}
}

func TestBigIntegerAccountingGrowsLinearly(t *testing.T) {
	var previousEncode, previousDecode DecodeUsage
	for _, size := range []uint{128, 256, 512} {
		value := new(big.Int).Lsh(big.NewInt(1), size*8-1)
		budget, err := EncodeBudget()
		if err != nil {
			t.Fatal(err)
		}
		bb := NewBudgetBuffer(budget)
		if err := EncodeIntegerBigBoundsAligned(bb, value, nil, nil, false); err != nil {
			t.Fatal(err)
		}
		encode := bb.Usage()
		if encode.AllocatedBytes < operationMetadataBytes+uint64(size)*8 {
			t.Fatalf("missing integer workspace: %+v", encode)
		}
		state := ApplyDecodeOptions()
		reader := NewBitBufferFromBytes(bb.CompleteBytes())
		if err := reader.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeIntegerBigBoundsAligned(reader, nil, nil, false)
		if err != nil || decoded.Cmp(value) != 0 {
			t.Fatal(err)
		}
		decode := reader.Usage()
		if decode.AllocatedBytes < operationMetadataBytes+uint64(size)*8 {
			t.Fatalf("missing decoded workspace: %+v", decode)
		}
		for _, pair := range [][2]DecodeUsage{{encode, previousEncode}, {decode, previousDecode}} {
			if pair[1].Work != 0 && (pair[0].Work > pair[1].Work*3 || pair[0].AllocatedBytes > pair[1].AllocatedBytes*3) {
				t.Fatalf("nonlinear integer workspace: %+v", pair)
			}
		}
		previousEncode, previousDecode = encode, decode
	}
}

func TestLargeIntegerFailureHasBoundedDiagnostic(t *testing.T) {
	value := new(big.Int).Lsh(big.NewInt(1), 1<<20)
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	bb := NewBudgetBuffer(budget)
	err = EncodeIntegerBigBoundsAligned(bb, value, big.NewInt(0), big.NewInt(10), false)
	if !errors.Is(err, ErrConstraintViolation) || len(err.Error()) > 256 || bb.BitPos() != 0 {
		t.Fatalf("unbounded integer diagnostic: %v", err)
	}
}

func TestOIDValidationScanIsCharged(t *testing.T) {
	state := ApplyDecodeOptions()
	reader := NewBitBufferFromBytes([]byte{3, 0x2a, 3, 4})
	if err := reader.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeObjectIdentifierAligned(reader); err != nil {
		t.Fatal(err)
	}
	// 32 read bits, one fragment, three 3-byte reservations/copies in the
	// octet reader, one 3-byte string copy and one 3-byte validation scan.
	if got := reader.Usage().Work; got != operationMetadataBytes+48 {
		t.Fatalf("OID scan work=%d", got)
	}
}
