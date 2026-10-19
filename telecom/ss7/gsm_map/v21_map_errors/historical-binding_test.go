// Code generated from the MAP historical binding regression contract. DO NOT EDIT.

package v21_map_errors

import (
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func TestHistoricalBindingSentinel(t *testing.T) {
	var codec ValueCodec[NoParameter]
	parameter := &ErrorValue[NoParameter]{Parameter: &NoParameter{}}
	for _, attempt := range []func() error{
		func() error { _, err := decodeErrorParameter([]byte{1}, false, codec); return err },
		func() error { _, err := decodeErrorParameter(nil, true, codec); return err },
		func() error { _, _, err := encodeErrorParameter(parameter, codec); return err },
	} {
		if err := attempt(); !errors.Is(err, ber.ErrInvalidBinding) {
			t.Fatalf("historical descriptor returned %v", err)
		}
	}
}
