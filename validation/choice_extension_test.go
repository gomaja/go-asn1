package validation

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
)

// ITU-T X.680 (02/2021) §§29.3, 52.7.3; X.690 (02/2021) §§8.1.1, 8.13.
func TestSGP22ActivationCodeRetrievalInfoUnknownExtension(t *testing.T) {
	// [4] does not claim the tag of any of this extensible CHOICE's
	// known [1], [2] or [3] alternatives.
	wire := []byte{0x84, 0x81, 0x01, 0x00}
	var decoded sgp22.ActivationCodeRetrievalInfo
	if err := decoded.UnmarshalBER(wire); err != nil {
		t.Fatalf("decode unknown alternative: %v", err)
	}
	if decoded.Choice != 0 || decoded.UnknownExtension == nil || !bytes.Equal(decoded.UnknownExtension.Element, wire) {
		t.Fatalf("unknown alternative was not retained: %#v", decoded)
	}
	wire[3] = 0xff
	want := []byte{0x84, 0x81, 0x01, 0x00}
	if !bytes.Equal(decoded.UnknownExtension.Element, want) {
		t.Fatal("unknown alternative aliases input")
	}
	got, err := decoded.MarshalBER()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("BER replay = %x, %v; want %x", got, err, want)
	}
	if _, err := decoded.MarshalDER(); err == nil {
		t.Fatal("DER accepted nonminimal length")
	}

	fresh := sgp22.ActivationCodeRetrievalInfo{UnknownExtension: &runtime.BERChoiceExtension{Element: []byte{0x84, 0x01, 0x00}}}
	got, err = fresh.MarshalBER()
	if err != nil || !bytes.Equal(got, []byte{0x84, 0x01, 0x00}) {
		t.Fatalf("fresh BER = %x, %v", got, err)
	}
	got, err = fresh.MarshalDER()
	if err != nil || !bytes.Equal(got, []byte{0x84, 0x01, 0x00}) {
		t.Fatalf("fresh DER = %x, %v", got, err)
	}
	fresh.UnknownExtension.Element[0] = 0x82
	if _, err := fresh.MarshalBER(); err == nil {
		t.Fatal("unknown alternative reused the known [2] tag")
	}
	fresh.UnknownExtension.Element[0] = 0x84
	fresh.Choice = sgp22.ActivationCodeRetrievalInfoChoiceRetryDelay
	if _, err := fresh.MarshalBER(); err == nil {
		t.Fatal("known and unknown alternatives both selected")
	}
	var invalid sgp22.ActivationCodeRetrievalInfo
	if err := invalid.UnmarshalBER([]byte{0xa2, 0x01, 0xff}); err == nil {
		t.Fatal("constructed form accepted for the known primitive [2] alternative")
	}
}

// ITU-T X.680 (02/2021) §§22.1, 22.4, 22.7.
func TestSGP22UICCCapabilityNamedBitPosition(t *testing.T) {
	value := sgp22.UICCCapability{Bytes: []byte{0x80}, BitLength: 1}
	if !value.Has(sgp22.UICCCapabilityContactlessSupport) {
		t.Fatal("contactlessSupport is not bit zero")
	}
}
