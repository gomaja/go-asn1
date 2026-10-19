package validation

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	maprt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// go-asn1 #183: a named BIT STRING whose set bits need more bits than any
// permitted length is outside its SIZE constraint (X.680 (02/2021) §51.5).
// Strict encoding reports it as a SIZE ValidationError, as tolerant encoding
// and strict decoding do. SupportedRAT-Types is SIZE (2..8); bit 8 needs 9.
func TestNamedBitStringSizeEncodeError(t *testing.T) {
	bits := maprt.BitString{Bytes: []byte{0x00, 0x80}, BitLength: 9}
	value := gsm_map.SGSNCapability{SupportedRATTypesIndicator: &bits}
	for mode, encode := range map[string]func() ([]byte, error){
		"strict BER": func() ([]byte, error) { return value.MarshalBER() },
		"fresh BER":  func() ([]byte, error) { return value.MarshalBER(mapber.WithoutBERReplay()) },
		"DER":        value.MarshalDER,
	} {
		_, err := encode()
		var refusal *mapber.ValidationError
		if !errors.As(err, &refusal) || !errors.Is(err, mapber.ErrInvalidValue) {
			t.Errorf("%s: error = %v; want a ValidationError", mode, err)
			continue
		}
		if refusal.Constraint != "SIZE (2..8)" || refusal.Path != "supportedRAT-TypesIndicator" ||
			refusal.Rule.Clause != "51.5" || refusal.ObservedLength == nil || *refusal.ObservedLength != 9 {
			t.Errorf("%s: refusal = %+v; want SIZE (2..8) at supportedRAT-TypesIndicator, §51.5, length 9", mode, refusal.Violation)
		}
	}
	var refusal *mapber.ValidationError
	if _, err := gsm_map.NewSupportedRATTypes(8); !errors.As(err, &refusal) || refusal.Constraint != "SIZE (2..8)" {
		t.Fatalf("NewSupportedRATTypes(8) error = %v; want a SIZE (2..8) ValidationError", err)
	}
}
