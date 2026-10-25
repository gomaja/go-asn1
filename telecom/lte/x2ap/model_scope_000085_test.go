// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestPublicOperationLimitBoundaries(t *testing.T) {
	wire := receiverUnknownWire(t, 8)
	setters := []struct {
		name                            string
		set                             func(uint64) aper.Limits
		decode, encode, build, validate bool
	}{
		{"input", func(n uint64) aper.Limits { return aper.Limits{MaxInputBytes: n} }, true, false, false, false},
		{"output", func(n uint64) aper.Limits { return aper.Limits{MaxOutputBytes: n} }, false, true, true, false},
		{"open", func(n uint64) aper.Limits { return aper.Limits{MaxOpenTypeBytes: n} }, true, true, true, true},
		{"depth", func(n uint64) aper.Limits { return aper.Limits{MaxDepth: n} }, true, true, true, true},
		{"elements", func(n uint64) aper.Limits { return aper.Limits{MaxElements: n} }, true, true, true, true},
		{"fragments", func(n uint64) aper.Limits { return aper.Limits{MaxFragments: n} }, true, true, true, true},
		{"work", func(n uint64) aper.Limits { return aper.Limits{MaxWork: n} }, true, true, true, true},
		{"allocation", func(n uint64) aper.Limits { return aper.Limits{MaxAllocatedBytes: n} }, true, true, true, true},
		{"reports", func(n uint64) aper.Limits { return aper.Limits{MaxReports: n} }, true, false, true, true},
	}
	var original s20.X2APPDU
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	for _, setter := range setters {
		ops := []struct {
			name    string
			enabled bool
			run     func(aper.Limits) error
		}{
			{"decode", setter.decode, func(limits aper.Limits) error {
				var v s20.X2APPDU
				_, err := v.UnmarshalAPER(wire, aper.WithLimits(limits))
				return err
			}},
			{"encode", setter.encode, func(limits aper.Limits) error {
				_, err := original.MarshalAPER(aper.WithEncodeLimits(limits))
				return err
			}},
			{"build", setter.build, func(limits aper.Limits) error {
				_, err := s21.NewX2APPDUInitiatingMessage(*original.InitiatingMessage, aper.WithBuildLimits(limits))
				return err
			}},
			{"validate", setter.validate, func(limits aper.Limits) error {
				_, err := s21.ValidateMessage(&original, aper.WithValidationLimits(limits))
				return err
			}},
		}
		for _, op := range ops {
			if !op.enabled {
				continue
			}
			t.Run(op.name+"/"+setter.name, func(t *testing.T) {
				// Locate a transition, then test both adjacent limits independently.
				var low uint64 = 1
				high := uint64(aper.DefaultLimits().MaxAllocatedBytes)
				for low < high {
					middle := low + (high-low)/2
					err := op.run(setter.set(middle))
					if errors.Is(err, aper.ErrLimit) {
						low = middle + 1
					} else if err != nil {
						t.Fatal(err)
					} else {
						high = middle
					}
				}
				required := low
				if required <= 1 {
					t.Fatalf("%s ceiling is not enforced", setter.name)
				}
				for _, limit := range []uint64{required - 1, required, required + 1} {
					err := op.run(setter.set(limit))
					if (limit < required) != errors.Is(err, aper.ErrLimit) {
						t.Fatalf("limit=%d required=%d err=%v", limit, required, err)
					}
				}
				t.Logf("minimum %s %s=%d", op.name, setter.name, required)
				if op.name == "decode" {
					for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
						var reused s20.X2APPDU
						for _, limit := range []uint64{required, required - 1, required + 1} {
							opts := append([]aper.DecodeOption{}, options...)
							opts = append(opts, aper.WithLimits(setter.set(limit)))
							report, err := reused.UnmarshalAPER(wire, opts...)
							if (limit < required) != errors.Is(err, aper.ErrLimit) {
								t.Fatalf("reused limit=%d report=%+v err=%v", limit, report, err)
							}
							if err != nil && reused.Choice != 0 {
								t.Fatal("limit retained old receiver")
							}
						}
					}
				}
			})
		}
	}
}
