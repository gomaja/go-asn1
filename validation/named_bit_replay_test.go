package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lpp"
)

// LPP CommonIEsRequestCapabilities carries lpp-message-segmentation-req-r14, a
// BIT STRING with named bits and no size constraint, in an extension
// addition group. pycrate 0.7.11 encodes it with the bit length given, from
// a module version with one addition group: '1'B in 1 bit, and the same
// abstract value in 64 and 72 bits. A received non-minimal value is replayed
// byte-exactly while unchanged (X.691 (02/2021) §§16.2, 16.3); a copy of up
// to eight octets is kept inline, a longer one in its own slice.
func TestNamedBitStringReplayLongValue(t *testing.T) {
	for _, tc := range []struct {
		bits int
		wire string
		kept bool
	}{
		{1, "8081406000", false},
		{64, "80855020000000000000000000", true},
		{72, "8085d22000000000000000000000", true},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		var value lpp.CommonIEsRequestCapabilities
		if err := value.UnmarshalUPER(wire); err != nil {
			t.Fatalf("%d bits: %v", tc.bits, err)
		}
		received := value.LppMessageSegmentationReqR14
		if received == nil || received.BitLength != tc.bits || received.Bytes[0] != 0x80 {
			t.Fatalf("%d bits: decoded %+v", tc.bits, received)
		}
		if kept := !value.PERPadding_.KeptBitString(0).IsZero(); kept != tc.kept {
			t.Fatalf("%d bits: kept = %v, want %v", tc.bits, kept, tc.kept)
		}
		if out, err := value.MarshalUPER(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%d bits: replay %x, %v; want %s", tc.bits, out, err, tc.wire)
		}
		fresh := lpp.CommonIEsRequestCapabilities{LppMessageSegmentationReqR14: &runtime.BitString{
			Bytes: append([]byte(nil), received.Bytes...), BitLength: received.BitLength}}
		out, err := fresh.MarshalUPER()
		if err != nil {
			t.Fatal(err)
		}
		var back lpp.CommonIEsRequestCapabilities
		if err := back.UnmarshalUPER(out); err != nil || back.LppMessageSegmentationReqR14 == nil || back.LppMessageSegmentationReqR14.BitLength != 1 {
			t.Fatalf("%d bits: fresh %x decodes as %+v, %v; want 1 bit", tc.bits, out, back.LppMessageSegmentationReqR14, err)
		}
	}
}
