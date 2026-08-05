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

func TestSendAuthenticationInfoResAcceptsEPSOnlyAuthenticationSetList(t *testing.T) {
	want := SendAuthenticationInfoRes{
		EpsAuthenticationSetList: EPSAuthenticationSetList{
			{
				Rand:  []byte{0x01},
				Xres:  []byte{0x02},
				Autn:  []byte{0x03},
				Kasme: []byte{0x04},
			},
		},
	}

	input, err := want.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}
	if !bytes.Contains(input, []byte{0xa2}) {
		t.Fatalf("MarshalBER = % x, want eps-AuthenticationSetList [2]", input)
	}

	var got SendAuthenticationInfoRes
	if err := got.UnmarshalBER(input); err != nil {
		t.Fatalf("UnmarshalBER EPS-only SendAuthenticationInfoRes: %v", err)
	}
	if got.AuthenticationSetList != nil {
		t.Fatalf("AuthenticationSetList = %+v, want nil", got.AuthenticationSetList)
	}
	if len(got.EpsAuthenticationSetList) != 1 {
		t.Fatalf("EpsAuthenticationSetList length = %d, want 1", len(got.EpsAuthenticationSetList))
	}
	elem := got.EpsAuthenticationSetList[0]
	if !bytes.Equal(elem.Rand, []byte{0x01}) ||
		!bytes.Equal(elem.Xres, []byte{0x02}) ||
		!bytes.Equal(elem.Autn, []byte{0x03}) ||
		!bytes.Equal(elem.Kasme, []byte{0x04}) {
		t.Fatalf("decoded EPC-AV = %+v", elem)
	}

	roundTrip, err := got.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER round-trip: %v", err)
	}
	if !bytes.Equal(roundTrip, input) {
		t.Fatalf("MarshalBER round-trip = % x, want % x", roundTrip, input)
	}
}
