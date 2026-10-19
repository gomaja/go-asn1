// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_context_external_test.go; SHA-256 51496614df6778f39b0d4d0fe049cab57ef328a5814c3e8ae6f308fecb225bf5.
package ber_test

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
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

func TestGeneratedDecodeContextRechecksAfterPreparation(t *testing.T) {
	options := ber.TrackBERForm([]ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()})
	owned, err := ber.OwnGeneratedBERInput([]byte{0x30, 0x03, 0x04, 0x01, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	prepared, context, err := ber.PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	prepared[3] = 5
	for _, test := range []struct {
		name  string
		check func() error
	}{
		{"root validation", func() error { return ber.ValidateBERElement(prepared, context...) }},
		{"child validation", func() error { return ber.ValidateBERElement(prepared[2:], ber.ChildDecodeContext(context, "value")) }},
		{"child preparation", func() error {
			_, _, err := ber.PrepareGeneratedBERInput(prepared[2:], []ber.DecodeOption{ber.ChildDecodeContext(context, "value")})
			return err
		}},
		{"child TLV", func() error {
			_, _, _, err := ber.DecodeTLV(prepared[2:], ber.ChildDecodeContext(context, "value"))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.check(); !errors.Is(err, ber.ErrTruncated) && !errors.Is(err, ber.ErrInvalidLength) {
				t.Fatalf("mutated input = %v, want a length error", err)
			}
		})
	}
}

func TestGeneratedDecodeContextRechecksPrimitiveContents(t *testing.T) {
	options := ber.TrackBERForm([]ber.DecodeOption{ber.ForceGeneratedBERProofForTesting()})
	owned, err := ber.OwnGeneratedBERInput([]byte{0x30, 0x03, 0x0c, 0x01, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	prepared, context, err := ber.PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	prepared[4] = 0xc3 // A truncated UTF-8 sequence within a valid TLV boundary.
	if err := ber.ValidateBERElement(prepared, options...); !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatalf("ordinary validation = %v, want invalid value", err)
	}
	child := []ber.DecodeOption{ber.ChildDecodeContext(context, "value")}
	for _, test := range []struct {
		name  string
		check func() error
	}{
		{"root validation", func() error { return ber.ValidateBERElement(prepared, context...) }},
		{"child validation", func() error { return ber.ValidateBERElement(prepared[2:], child...) }},
		{"child ownership", func() error { _, err := ber.OwnGeneratedBERInput(prepared[2:], child); return err }},
		{"child preparation", func() error { _, _, err := ber.PrepareGeneratedBERInput(prepared[2:], child); return err }},
		{"child TLV", func() error { _, _, _, err := ber.DecodeTLV(prepared[2:], child...); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.check(); !errors.Is(err, ber.ErrInvalidValue) {
				t.Fatalf("mutated primitive = %v, want invalid value", err)
			}
		})
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
