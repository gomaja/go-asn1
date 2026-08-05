package sgp22

import (
	"bytes"
	"testing"
	"time"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestExpirationDateUsesPKIXTime(t *testing.T) {
	want := time.Date(2049, time.December, 31, 23, 59, 59, 0, time.UTC)
	v := ExpirationDate(NewTimeUtcTime(want))

	encoded, err := v.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER() error = %v", err)
	}

	var decoded ExpirationDate
	if err := decoded.UnmarshalBER(encoded); err != nil {
		t.Fatalf("UnmarshalBER() error = %v", err)
	}
	if decoded.Choice != TimeChoiceUtcTime {
		t.Fatalf("decoded choice = %d, want %d", decoded.Choice, TimeChoiceUtcTime)
	}
	if decoded.UtcTime == nil || !decoded.UtcTime.Equal(want) {
		t.Fatalf("decoded utcTime = %v, want %v", decoded.UtcTime, want)
	}
}

func TestTaggedResponseChoicesPreserveOuterTags(t *testing.T) {
	tx := TransactionId{0x01, 0x02, 0x03}

	prepareError := PrepareDownloadResponseError{
		TransactionId:     tx,
		DownloadErrorCode: DownloadErrorCodeNoSessionContext,
	}
	authenticateError := AuthenticateResponseError{
		TransactionId:         tx,
		AuthenticateErrorCode: AuthenticateErrorCodeNoSessionContext,
	}

	prepareInner := mustImplicitChoice(t, 1, true, &prepareError)
	authenticateInner := mustImplicitChoice(t, 1, true, &authenticateError)
	integerErrorInner := ber.EncodeImplicitTagWithClass(
		tag.ClassContextSpecific,
		1,
		false,
		ber.EncodeInteger(127),
	)

	tests := []struct {
		name       string
		tagNumber  int
		inner      []byte
		wantChoice int
		marshal    func() ([]byte, error)
		unmarshal  func([]byte) (int, error)
	}{
		{
			name:       "PrepareDownloadResponse",
			tagNumber:  33,
			inner:      prepareInner,
			wantChoice: PrepareDownloadResponseChoiceDownloadResponseError,
			marshal: func() ([]byte, error) {
				v := NewPrepareDownloadResponseDownloadResponseError(prepareError)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v PrepareDownloadResponse
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "AuthenticateServerResponse",
			tagNumber:  56,
			inner:      authenticateInner,
			wantChoice: AuthenticateServerResponseChoiceAuthenticateResponseError,
			marshal: func() ([]byte, error) {
				v := NewAuthenticateServerResponseAuthenticateResponseError(authenticateError)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v AuthenticateServerResponse
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "CancelSessionResponse",
			tagNumber:  65,
			inner:      integerErrorInner,
			wantChoice: CancelSessionResponseChoiceCancelSessionResponseError,
			marshal: func() ([]byte, error) {
				v := NewCancelSessionResponseCancelSessionResponseError(127)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v CancelSessionResponse
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "AuthenticateClientResponseEs9",
			tagNumber:  59,
			inner:      integerErrorInner,
			wantChoice: AuthenticateClientResponseEs9ChoiceAuthenticateClientError,
			marshal: func() ([]byte, error) {
				v := NewAuthenticateClientResponseEs9AuthenticateClientError(127)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v AuthenticateClientResponseEs9
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "GetBoundProfilePackageResponse",
			tagNumber:  58,
			inner:      integerErrorInner,
			wantChoice: GetBoundProfilePackageResponseChoiceGetBoundProfilePackageError,
			marshal: func() ([]byte, error) {
				v := NewGetBoundProfilePackageResponseGetBoundProfilePackageError(127)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v GetBoundProfilePackageResponse
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "CancelSessionResponseEs9",
			tagNumber:  65,
			inner:      integerErrorInner,
			wantChoice: CancelSessionResponseEs9ChoiceCancelSessionError,
			marshal: func() ([]byte, error) {
				v := NewCancelSessionResponseEs9CancelSessionError(127)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v CancelSessionResponseEs9
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
		{
			name:       "AuthenticateClientResponseEs11",
			tagNumber:  64,
			inner:      integerErrorInner,
			wantChoice: AuthenticateClientResponseEs11ChoiceAuthenticateClientError,
			marshal: func() ([]byte, error) {
				v := NewAuthenticateClientResponseEs11AuthenticateClientError(127)
				return v.MarshalBER()
			},
			unmarshal: func(data []byte) (int, error) {
				var v AuthenticateClientResponseEs11
				err := v.UnmarshalBER(data)
				return v.Choice, err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := encodeOuterTaggedChoice(tc.tagNumber, tc.inner)

			got, err := tc.marshal()
			if err != nil {
				t.Fatalf("MarshalBER() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("MarshalBER() = %x, want %x", got, want)
			}

			gotChoice, err := tc.unmarshal(want)
			if err != nil {
				t.Fatalf("UnmarshalBER() error = %v", err)
			}
			if gotChoice != tc.wantChoice {
				t.Fatalf("decoded choice = %d, want %d", gotChoice, tc.wantChoice)
			}

			if _, err := tc.unmarshal(tc.inner); err == nil {
				t.Fatalf("UnmarshalBER() accepted inner choice without outer tag")
			}
		})
	}
}

type berMarshaler interface {
	MarshalBER() ([]byte, error)
}

func mustImplicitChoice(t *testing.T, tagNumber int, constructed bool, v berMarshaler) []byte {
	t.Helper()

	encoded, err := v.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER() error = %v", err)
	}
	return ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, tagNumber, constructed, encoded)
}

func encodeOuterTaggedChoice(tagNumber int, inner []byte) []byte {
	return ber.EncodeConstructed(tag.Tag{
		Class:       tag.ClassContextSpecific,
		Number:      tagNumber,
		Constructed: true,
	}, inner)
}
