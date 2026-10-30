package gsm_map_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/bindings"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// X.690 (02/2021) §8.5 applies to a received REAL even when the MAP
// abstract syntax expects an OCTET STRING and would reject its identifier.
func TestUnexpectedRealContents(t *testing.T) {
	for _, row := range []struct {
		wire         string
		scan, decode error
	}{
		{"0903b00001", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090183", ber.ErrTruncated, ber.ErrTruncated},
		{"090100", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090144", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"090140", nil, ber.ErrUnexpectedElement},
		{"0903800001", nil, ber.ErrUnexpectedElement},
		{"050100", ber.ErrInvalidValue, ber.ErrInvalidValue},
	} {
		t.Run(row.wire, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			scan := ber.ValidateBERElement(data)
			for _, options := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}} {
				_, decode := bindings.IMSICodec().DecodeBER(data, options...)
				for _, pair := range [][2]error{{scan, row.scan}, {decode, row.decode}} {
					if (pair[0] == nil) != (pair[1] == nil) {
						t.Fatalf("got %v, want %v", pair[0], pair[1])
					}
					for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit, ber.ErrInvalidCodec, ber.ErrInvalidBinding} {
						if errors.Is(pair[0], sentinel) != (pair[1] == sentinel) {
							t.Fatalf("got %v, want %v (sentinel %v)", pair[0], pair[1], sentinel)
						}
					}
				}
			}
		})
	}
}
