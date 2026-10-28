package gsm_map

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func TestNestedDecodeErrorTextNamesPathOnce(t *testing.T) {
	data, err := hex.DecodeString("300f0403010203810101040101a6028000")
	if err != nil {
		t.Fatal(err)
	}
	var value UpdateLocationArg
	err = value.UnmarshalBER(data)
	var path interface{ ASN1BERPath() string }
	var location *ber.ElementError
	if !errors.As(err, &path) || path.ASN1BERPath() != "vlr-Capability.supportedCamelPhases" || !errors.As(err, &location) || !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatalf("cause/path missing: %v", err)
	}
	cause := errors.Unwrap(err)
	if got, want := err.Error(), "decoding vlr-Capability.supportedCamelPhases: ber: invalid value encoding: empty BIT STRING value"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	var retained *ber.ElementError
	if errors.Unwrap(err) != cause || !errors.As(err, &retained) || retained != location {
		t.Fatal("formatting changed cause")
	}
}
