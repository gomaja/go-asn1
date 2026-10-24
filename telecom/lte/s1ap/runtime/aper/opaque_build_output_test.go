// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/opaque_build_output_test.go; SHA-256 2540025eeb7cfd7d67f1ccd9491b9b5560cba9311a195cdabc459f1074f57c01.
package aper

import (
	"bytes"
	"errors"
	"testing"
)

func TestOpaqueBuildOutputBoundary(t *testing.T) {
	for _, limit := range []uint64{2, 3, 4} {
		budget, err := BuildBudget(WithBuildLimits(Limits{MaxOutputBytes: limit}))
		if err != nil {
			t.Fatal(err)
		}
		value, err := BuildOpaqueOpenType([]byte{1, 2, 3}, budget)
		if (limit < 3) != errors.Is(err, ErrLimit) {
			t.Fatalf("limit=%d error=%v", limit, err)
		}
		if err == nil && !bytes.Equal(value.Bytes(), []byte{1, 2, 3}) {
			t.Fatal("built contents differ")
		}
		if err != nil && NewBudgetBuffer(budget).Usage().AllocatedBytes != operationMetadataBytes {
			t.Fatal("output failure copied contents")
		}
	}
}
