package rrc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
)

// TS 25.331 V19.0.1 12.1.3 requires receiver tolerance for extension and
// padding parts; X.691 (02/2021) 11.1.3.2 still makes these senders invalid.
func TestInterRATHandoverNonstandardPaddingOption(t *testing.T) {
	for _, tc := range []struct {
		name, input         string
		contained, trailing int
	}{
		{"contained-zero-padding", "19408000", 6, 0},
		{"top-level-zero-octets", "1940200000", 0, 18},
		{"top-level-nonzero-bits", "19402000052150", 0, 34},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			var strict InterRATHandoverInfo
			if err := strict.UnmarshalUPER(input); err == nil {
				t.Fatal("strict decode accepted non-conformant input")
			}
			var decoded InterRATHandoverInfo
			if err := decoded.UnmarshalUPERWithOptions(input, per.DecodeOptions{AllowNonstandardTrailingBits: true}); err != nil {
				t.Fatal(err)
			}
			if decoded.PERExtraBits_.BitLength != tc.trailing {
				t.Fatalf("trailing length = %d, want %d", decoded.PERExtraBits_.BitLength, tc.trailing)
			}
			if tc.contained != 0 {
				p := decoded.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions.PERContainedPadding_["interRATHandoverInfo-r3-add-ext"]
				_, count := p.Bits()
				if int(count) != tc.contained {
					t.Fatalf("contained padding = %d, want %d", count, tc.contained)
				}
			}
			wire, err := decoded.MarshalUPER()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, input) {
				t.Fatalf("round trip = %x, want %x", wire, input)
			}
		})
	}
}
