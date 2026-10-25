// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReplayedStandaloneBodyEnforcesOpenCeiling(t *testing.T) {
	field, err := s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s20.NewErrorIndication(s11.ErrorIndicationIEContainer{field})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded s20.ErrorIndication
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	limits := aper.Limits{MaxOpenTypeBytes: 1}
	for _, options := range [][]aper.EncodeOption{{aper.WithEncodeLimits(limits)}, {aper.WithEncodeLimits(limits), aper.WithoutReplay()}} {
		if _, err := decoded.MarshalAPER(options...); !errors.Is(err, aper.ErrLimit) {
			t.Fatalf("standalone field exceeded open ceiling: %v", err)
		}
	}
	if _, err := s20.ValidateErrorIndication(&decoded, aper.WithValidationLimits(limits)); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("standalone validation exceeded open ceiling: %v", err)
	}
	if _, err := s20.NewErrorIndication(decoded.ProtocolIEs, aper.WithBuildLimits(limits)); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("standalone build exceeded open ceiling: %v", err)
	}
}
