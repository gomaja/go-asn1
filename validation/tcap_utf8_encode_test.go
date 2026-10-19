package validation

import (
	"bytes"
	"errors"
	"testing"

	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #182: TCAP's modules have no UTF8String, but its runtime helper
// must not emit what DecodeStringValueTag refuses (X.690 (02/2021) §8.23.10).
func TestTCAPUTF8StringHelperRefusesInvalidText(t *testing.T) {
	if got, err := tcapber.EncodeStringTagChecked(12, "\xff"); !errors.Is(err, tcapber.ErrInvalidValue) {
		t.Fatalf("EncodeStringTagChecked(12, \"\\xff\") = %x, %v; want ErrInvalidValue", got, err)
	}
	if _, err := tcapber.DecodeStringValueTag(12, []byte{0xff}); !errors.Is(err, tcapber.ErrInvalidValue) {
		t.Fatalf("DecodeStringValueTag(12, ff) = %v; want ErrInvalidValue", err)
	}
	if got, err := tcapber.EncodeStringTagChecked(12, "é"); err != nil || !bytes.Equal(got, mustHex(t, "0c02c3a9")) {
		t.Fatalf("EncodeStringTagChecked(12, \"é\") = %x, %v; want 0c02c3a9", got, err)
	}
}
