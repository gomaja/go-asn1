// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_context_external_test.go; SHA-256 196b80a539d5e8eeafc516524d7eeee7deb2e2f4b44283b6bac7db8d1198f867.
package ber_test

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"testing"
)

func TestGeneratedDecodeContextRejectsMutatedOwnedInput(t *testing.T) {
	options := ber.TrackBERForm([]ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()})
	owned, err := ber.OwnGeneratedBERInput([]byte{0x30, 0x03, 0x04, 0x01, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	owned[3] = 5
	if err := ber.ValidateBERElement(owned, options...); !errors.Is(err, ber.ErrTruncated) && !errors.Is(err, ber.ErrInvalidLength) {
		t.Fatalf("mutated input was not rejected by ordinary validation: %v", err)
	}
	prepared, context, err := ber.PrepareGeneratedBERInput(owned, options)
	if err == nil {
		if err := ber.ValidateBERElement(prepared, context...); err == nil {
			t.Fatal("stale generated context accepted mutated invalid input")
		}
	}
}

func TestGeneratedDecodeContextAppliesLaterLimits(t *testing.T) {
	options := ber.TrackBERForm([]ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()})
	owned, err := ber.OwnGeneratedBERInput([]byte{0x30, 0x06, 0x04, 0x01, 'A', 0x04, 0x01, 'B'}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	strictRoot := append(append([]ber.DecodeOption(nil), options...), ber.WithDecodeLimits(ber.DecodeLimits{MaxElements: 1}))
	if _, _, err := ber.PrepareGeneratedBERInput(owned, strictRoot); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatalf("root preparation with a tighter limit = %v, want resource limit", err)
	}
	prepared, context, err := ber.PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	strict := append(append([]ber.DecodeOption(nil), context...), ber.WithDecodeLimits(ber.DecodeLimits{MaxElements: 1}))
	if err := ber.ValidateBERElement(prepared, strict...); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatalf("validation with a tighter limit = %v, want resource limit", err)
	}
	if _, _, err := ber.PrepareGeneratedBERInput(prepared, strict); !errors.Is(err, ber.ErrResourceLimit) {
		t.Fatalf("preparation with a tighter limit = %v, want resource limit", err)
	}
}

func TestGeneratedDecodeContextRechecksReconstructedInput(t *testing.T) {
	options := ber.TrackBERForm([]ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()})
	owned, err := ber.OwnGeneratedBERInput([]byte{0x80, 0x01, 0x00}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	_, context, err := ber.PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed := []byte{0x01, 0x01, 0x00}
	if err := ber.ValidateBERElement(reconstructed, context...); err != nil {
		t.Fatal(err)
	}
	reconstructed[1] = 2
	if _, _, err := ber.PrepareGeneratedBERInput(reconstructed, context); !errors.Is(err, ber.ErrTruncated) && !errors.Is(err, ber.ErrInvalidLength) {
		t.Fatalf("mutated reconstructed input = %v, want a length error", err)
	}
}
