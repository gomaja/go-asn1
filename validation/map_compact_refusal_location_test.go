package validation

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	maprt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// A standalone named-bit codec's strict refusal names the same source and
// path as its tolerant record. SupportedRAT-Types is SIZE (2..8), and bit 8
// needs 9 bits (X.680 (02/2021) §51.5).
func TestMAPCompactNamedBitRefusalLocation(t *testing.T) {
	const source, path = "MAP-MS-DataTypes.SupportedRAT-Types", "SupportedRAT-Types"
	value := gsm_map.BERValue[gsm_map.SupportedRATTypes]{Value: maprt.BitString{Bytes: []byte{0x00, 0x80}, BitLength: 9}}
	codec := gsm_map.SupportedRATTypesCodec()
	for mode, encode := range map[string]func() ([]byte, error){
		"BER":       func() ([]byte, error) { return codec.EncodeBER(value) },
		"fresh BER": func() ([]byte, error) { return codec.EncodeBER(value, mapber.WithoutBERReplay()) },
		"DER":       func() ([]byte, error) { return codec.EncodeDER(value) },
	} {
		_, err := encode()
		var refusal *mapber.ValidationError
		if !errors.As(err, &refusal) || refusal.Constraint != "SIZE (2..8)" || refusal.Source != source || refusal.Path != path {
			t.Errorf("%s: refusal = %v; want SIZE (2..8) at %s, %s", mode, err, source, path)
		}
	}
	var refusal *mapber.ValidationError
	if _, err := gsm_map.NewSupportedRATTypes(8); !errors.As(err, &refusal) || refusal.Source != source || refusal.Path != path {
		t.Errorf("NewSupportedRATTypes(8) = %v; want SIZE (2..8) at %s, %s", err, source, path)
	}
}
