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
	const containedPath = "InterRATHandoverInfo.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions.InterRATHandoverInfoR3AddExt"
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
			var tolerated per.ToleranceLog
			var decoded InterRATHandoverInfo
			if err := decoded.UnmarshalUPERWithOptions(input, per.DecodeOptions{TrailingBitsTolerance: &tolerated}); err != nil {
				t.Fatal(err)
			}
			if trailing := decoded.PERPadding_.Trailing(); trailing.BitLength != tc.trailing {
				t.Fatalf("trailing length = %d, want %d", trailing.BitLength, tc.trailing)
			}
			_, count := decoded.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions.InterRATHandoverInfoR3AddExtPERPadding_.Bits()
			if int(count) != tc.contained {
				t.Fatalf("contained padding = %d, want %d", count, tc.contained)
			}
			records := tolerated.Snapshot()
			if len(records) != 1 {
				t.Fatalf("tolerance records = %+v, want one", records)
			}
			record := records[0]
			switch {
			// The contained InterRATHandoverInfo-r3-add-ext-IEs value is two
			// bits, so the padding starts at offset 2 of the BIT STRING.
			case tc.contained != 0 && (record.Path != containedPath || record.Kind != per.ToleratedContainedPadding || record.Bits.BitLength != tc.contained || record.Offset != 2):
				t.Fatalf("record = %+v, want %d contained padding bits at %s", record, tc.contained, containedPath)
			case tc.trailing != 0 && (record.Path != "InterRATHandoverInfo" || record.Kind != per.ToleratedTrailingBits || record.Bits.BitLength != tc.trailing ||
				!bytes.Equal(record.Bits.Bytes, decoded.PERPadding_.Trailing().Bytes) || record.Offset+tc.trailing != 8*len(input)):
				t.Fatalf("record = %+v, want %d trailing bits", record, tc.trailing)
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
