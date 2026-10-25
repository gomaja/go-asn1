// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	errors "errors"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

// X.691 (02/2021) §§11.1.4 and 11.2.1: a known open value is a
// complete encoding, with alignment and full consumption checked in one pass.
// All octets below are synthetic source-derived controls and mutations.
func TestKnownMalformedOpenValuesNeverBecomeOpaque(t *testing.T) {
	cases := []struct {
		name, typ, wire string
		valid           bool
	}{
		{"s1ap-61-baseline", "S1APPDU", "4011000e0000020002400200000041400120", true},
		{"s1ap-61-timetowait-extra-octet", "S1APPDU", "4011000f0000020002400200000041400220ee", false},
		{"s1ap-61-cause-extra-octet", "S1APPDU", "4011000f000002000240030000ee0041400120", false},
		{"s1ap-61-pdu-value-extra-octet", "S1APPDU", "401100090000010041400120ee", false},
		{"s1ap-61-mme-ue-s1ap-id-extra-octets", "S1APPDU", "2017001100000200004004002aeeee000840020007", false},
		{"erab-information-daps-extension-recursive", "ERABInformationListItem", "250000013d400100", true},
		{"erab-information-malformed-daps-full-path", "ERABInformationListItem", "250000013d4001ff", false},
		{"s1ap-pdu-constrained-header", "S1APPDU", "002e0002bbcc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			var encoded []byte
			switch tc.typ {
			case "S1APPDU":
				var value s53.S1APPDU
				_, err = value.UnmarshalAPER(wire)
				if err == nil {
					encoded, err = value.MarshalAPER()
				}
				if !tc.valid && (value.InitiatingMessage != nil || value.UnsuccessfulOutcome != nil || value.Choice != 0) {
					t.Fatal("failed decode published a partial value")
				}
			case "ERABInformationListItem":
				var value s29.ERABInformationListItem
				_, err = value.UnmarshalAPER(wire)
				if err == nil {
					encoded, err = value.MarshalAPER()
				}
			default:
				t.Fatal("unhandled synthetic type")
			}
			if tc.valid {
				if err != nil || !bytes.Equal(wire, encoded) {
					t.Fatalf("control replay=%x err=%v", encoded, err)
				}
				return
			}
			if err == nil {
				t.Fatal("malformed known value accepted")
			}
			var located *runtime.DecodePathError
			if !errors.As(err, &located) || located.Path == "" {
				t.Fatalf("malformed known value lost location: %v", err)
			}
			if strings.Contains(tc.name, "extra-octet") && !errors.Is(err, aper.ErrExtraData) {
				t.Fatalf("wrong complete-consumption class: %v", err)
			}
		})
	}
}
