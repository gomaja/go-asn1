// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/external_context_guard_test.go; SHA-256 369c6bf2e23ea3e5ee6c802bef88f51d7807b41aa05178a0f1a775abd07373b6.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// X.690 (02/2021) §§8.9.2, 8.18.9, 8.23.10: only an unchanged
// element covered by this decode's preflight can reuse that validation.
func TestExternalContextValidationScope(t *testing.T) {
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{
		{"adaptive", nil}, {"light", ForceGeneratedBERLightForTesting()}, {"proof", ForceGeneratedBERProofForTesting()},
	} {
		for _, implicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/implicit=%t", mode.name, implicit), func(t *testing.T) {
				prepare := func(wire []byte) ([]byte, []DecodeOption) {
					t.Helper()
					var options []DecodeOption
					if mode.option != nil {
						options = append(options, mode.option)
					}
					options = TrackBERForm(options)
					owned, err := OwnGeneratedBERInput(wire, options)
					if err != nil {
						t.Fatal(err)
					}
					data, context, err := PrepareGeneratedBERInput(owned, options)
					if err != nil {
						t.Fatal(err)
					}
					return data, context
				}
				decode := func(data []byte, options []DecodeOption) error {
					t.Helper()
					if implicit {
						_, err := DecodeExternalValue(data[2:], options...)
						return err
					}
					_, _, err := DecodeExternal(data, options...)
					return err
				}
				wire := structureWire(t, "280a060130a00530030c0141")
				data, options := prepare(wire)
				if err := decode(data, options); err != nil {
					t.Fatal(err)
				}
				// Detached bytes have no ownership proof, even if their framing matches.
				detached := bytes.Clone(data)
				detached[len(detached)-1] = 0xff
				if err := decode(detached, options); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("detached UTF8String: %v", err)
				}
				// A changed working span must not inherit its earlier validation.
				data[len(data)-1] = 0xff
				if err := decode(data, options); !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("changed UTF8String: %v", err)
				}
				// Neither a form marker nor a location alone claims generated preflight.
				malformed := structureWire(t, "280b060130a006300430303030")
				for _, opts := range [][]DecodeOption{nil, TrackBERForm(nil), LocateDecodedElement(malformed, "Standalone.external", nil)} {
					if err := decode(malformed, opts); !errors.Is(err, ErrTruncated) {
						t.Fatalf("unvalidated structural value: %v", err)
					}
				}
				// Bytes inside a primitive value were never traversed as BER children.
				primitive := append(append([]byte{4}, EncodeLength(len(malformed))...), malformed...)
				data, options = prepare(primitive)
				_, _, contents, err := DecodeTLV(data)
				if err != nil {
					t.Fatal(err)
				}
				if err := decode(contents, options); !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("primitive contents: %v", err)
				}
			})
		}
	}
}
