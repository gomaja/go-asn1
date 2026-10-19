// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/depth_overflow_test.go; SHA-256 6d71e14721c87e6867422fc7effd59f916b3c14427758e687a4b49947a2aeb9c.
package ber

import (
	"math"
	"testing"
)

func TestNestedDecodeRejectsDepthOverflow(t *testing.T) {
	limits := DecodeLimits{MaxDepth: math.MaxInt, MaxElements: math.MaxInt, MaxWork: math.MaxInt}
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{
			name: "DER",
			fn: func() error {
				_, err := validateDERTLV([]byte{0x30, 0x02, 0x05, 0x00}, math.MaxInt, math.MaxInt, 0)
				return err
			},
		},
		{
			name: "constructed BIT STRING",
			fn: func() error {
				_, _, err := decodeBitStringValueBounded(true, []byte{0x03, 0x02, 0x00, 0xff}, math.MaxInt, &berWorkBudget{limits: limits})
				return err
			},
		},
		{
			name: "constructed OCTET STRING",
			fn: func() error {
				_, _, err := decodeOctetStringBounded([]byte{0x24, 0x03, 0x04, 0x01, 0xff}, math.MaxInt, &berWorkBudget{limits: limits})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatal("nested decode at maximum host depth succeeded")
			}
		})
	}
}
