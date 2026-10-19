package validation

import (
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	maprt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// go-asn1 #147: X.680 (02/2021) §22.7 lets encoding rules add or remove
// trailing 0 bits of a named BIT STRING. Fresh BER pads to the smallest
// permitted length (X.690 (02/2021) §8.6.2.4), DER removes trailing 0 bits
// (§11.2.2), and the decoder delivers a value that satisfies the SIZE
// constraint. AdditionalSubscriptions is BIT STRING {…} (SIZE (3..8)).
func TestNamedBitStringEncodesEquivalentLengths(t *testing.T) {
	built, err := gsm_map.NewAdditionalSubscriptions(0)
	if err != nil {
		t.Fatalf("NewAdditionalSubscriptions: %v", err)
	}
	for _, value := range []maprt.BitString{
		built,
		{Bytes: []byte{0x80}, BitLength: 1},
		{Bytes: []byte{0x80}, BitLength: 3},
		{Bytes: []byte{0x80}, BitLength: 8},
	} {
		message := gsm_map.SendGroupCallInfoRes{AdditionalSubscriptions: &value}
		ber, err := message.MarshalBER()
		if err != nil || hex.EncodeToString(ber) != "300484020580" {
			t.Fatalf("BitLength %d: MarshalBER = %x, %v; want 300484020580", value.BitLength, ber, err)
		}
		der, err := message.MarshalDER()
		if err != nil || hex.EncodeToString(der) != "300484020780" {
			t.Fatalf("BitLength %d: MarshalDER = %x, %v; want 300484020780", value.BitLength, der, err)
		}
	}
	var decoded gsm_map.SendGroupCallInfoRes
	if err := decoded.UnmarshalBER(mustHex(t, "300484020780")); err != nil {
		t.Fatalf("decode of the 1-bit form: %v", err)
	}
	if got := decoded.AdditionalSubscriptions; got == nil || got.BitLength != 3 || !got.Has(0) {
		t.Fatalf("decoded %+v; want BitLength 3 with bit 0 set", got)
	}
}
