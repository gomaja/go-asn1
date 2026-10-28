package gsm_map

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// X.680 (02/2021) §§25.6, 29 and X.690 (02/2021) §§8.1, 8.9.
func TestMAPElementMismatchSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"missing required", []byte{0x30, 0}, ber.ErrUnexpectedElement},
		{"wrong outer tag", []byte{0x31, 0}, ber.ErrUnexpectedElement},
		{"primitive SEQUENCE", []byte{0x10, 0}, ber.ErrInvalidTag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value MAPRefuseInfo
			err := value.UnmarshalBER(tc.wire)
			for _, sentinel := range []error{ber.ErrUnexpectedElement, ber.ErrInvalidTag, ber.ErrTruncated, ber.ErrExtraData} {
				if errors.Is(err, sentinel) != (sentinel == tc.want) {
					t.Errorf("%x: %v matches %v = %v", tc.wire, err, sentinel, errors.Is(err, sentinel))
				}
			}
		})
	}
	if got := ber.ValidateBERElement([]byte{0x30, 0}, ber.TrackMAPForm(nil)...); !errors.Is(got, ber.ErrInvalidValue) {
		t.Fatalf("standalone MAP profile scan = %v", got)
	}
}
