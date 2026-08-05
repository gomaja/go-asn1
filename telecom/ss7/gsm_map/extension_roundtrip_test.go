package gsm_map

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
)

func TestEmptyExtensionOnlySequencesPreserveRawExtensions(t *testing.T) {
	input := []byte{0x30, 0x03, 0x80, 0x01, 0x00}
	extension := []byte{0x80, 0x01, 0x00}

	tests := []struct {
		name  string
		check func(*testing.T, []byte, []byte)
	}{
		{
			name: "PCSExtensions",
			check: func(t *testing.T, data []byte, wantExt []byte) {
				var v PCSExtensions
				if err := v.UnmarshalBER(data); err != nil {
					t.Fatalf("UnmarshalBER: %v", err)
				}
				assertExtensionRoundTrip(t, v.ExtData_, wantExt, data, v.MarshalBER)
			},
		},
		{
			name: "LongTermDenialParam",
			check: func(t *testing.T, data []byte, wantExt []byte) {
				var v LongTermDenialParam
				if err := v.UnmarshalBER(data); err != nil {
					t.Fatalf("UnmarshalBER: %v", err)
				}
				assertExtensionRoundTrip(t, v.ExtData_, wantExt, data, v.MarshalBER)
			},
		},
		{
			name: "ShortTermDenialParam",
			check: func(t *testing.T, data []byte, wantExt []byte) {
				var v ShortTermDenialParam
				if err := v.UnmarshalBER(data); err != nil {
					t.Fatalf("UnmarshalBER: %v", err)
				}
				assertExtensionRoundTrip(t, v.ExtData_, wantExt, data, v.MarshalBER)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, input, extension)
		})
	}
}

func assertExtensionRoundTrip(t *testing.T, gotExt [][]byte, wantExt []byte, wantBER []byte, marshal func() ([]byte, error)) {
	t.Helper()
	if len(gotExt) != 1 || !bytes.Equal(gotExt[0], wantExt) {
		t.Fatalf("ExtData_ = %x, want [%x]", gotExt, wantExt)
	}
	encoded, err := marshal()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}
	if !bytes.Equal(encoded, wantBER) {
		t.Fatalf("MarshalBER = %x, want %x", encoded, wantBER)
	}
}

func TestAlertServiceCentreArgMarshalDERRejectsIndefiniteRawExtension(t *testing.T) {
	v := AlertServiceCentreArg{
		Msisdn:               []byte{0x01},
		ServiceCentreAddress: []byte{0x02},
		ExtData_: [][]byte{
			{0x30, 0x80, 0x05, 0x00, 0x00, 0x00},
		},
	}

	encoded, err := v.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}
	if !bytes.Contains(encoded, []byte{0x30, 0x80}) {
		t.Fatalf("MarshalBER = %x, want preserved indefinite raw extension", encoded)
	}

	_, err = v.MarshalDER()
	if !errors.Is(err, ber.ErrIndefiniteLength) {
		t.Fatalf("MarshalDER error = %v, want %v", err, ber.ErrIndefiniteLength)
	}
}
