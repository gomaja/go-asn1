package sgp32

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
)

func TestEsipaMessageFromIpaToEimPreservesTransferResponseChoiceTLV(t *testing.T) {
	transfer := NewTransferEimPackageResponseEimPackageReceived(struct{}{})
	msg := NewEsipaMessageFromIpaToEimTransferEimPackageResponse(transfer)

	got, err := msg.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER() error = %v", err)
	}
	want := ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, ber.EncodeNull())
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalBER() = %x, want %x", got, want)
	}

	var decoded EsipaMessageFromIpaToEim
	if err := decoded.UnmarshalBER(want); err != nil {
		t.Fatalf("UnmarshalBER() error = %v", err)
	}
	if decoded.Choice != EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse {
		t.Fatalf("decoded choice = %d, want %d", decoded.Choice, EsipaMessageFromIpaToEimChoiceTransferEimPackageResponse)
	}
	if decoded.TransferEimPackageResponse == nil ||
		decoded.TransferEimPackageResponse.Choice != TransferEimPackageResponseChoiceEimPackageReceived {
		t.Fatalf("decoded transfer response = %#v", decoded.TransferEimPackageResponse)
	}
}

func TestEsipaMessageFromEimToIpaPreservesTransferRequestChoiceTLV(t *testing.T) {
	request := NewTransferEimPackageRequestIpaEuiccDataRequest(IpaEuiccDataRequest{
		TagList: []byte{},
	})
	msg := NewEsipaMessageFromEimToIpaTransferEimPackageRequest(request)

	got, err := msg.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER() error = %v", err)
	}
	inner := ber.EncodeConstructed(tag.Tag{
		Class:       tag.ClassContextSpecific,
		Number:      82,
		Constructed: true,
	}, ber.EncodeTLV(tag.Tag{Class: tag.ClassApplication, Number: 28}, nil))
	want := ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 78, inner)
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalBER() = %x, want %x", got, want)
	}

	var decoded EsipaMessageFromEimToIpa
	if err := decoded.UnmarshalBER(want); err != nil {
		t.Fatalf("UnmarshalBER() error = %v", err)
	}
	if decoded.Choice != EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest {
		t.Fatalf("decoded choice = %d, want %d", decoded.Choice, EsipaMessageFromEimToIpaChoiceTransferEimPackageRequest)
	}
	if decoded.TransferEimPackageRequest == nil ||
		decoded.TransferEimPackageRequest.Choice != TransferEimPackageRequestChoiceIpaEuiccDataRequest {
		t.Fatalf("decoded transfer request = %#v", decoded.TransferEimPackageRequest)
	}
}

func TestTransferEimPackageResponsePreservesEuiccPackageResultChoiceTLV(t *testing.T) {
	result := NewEuiccPackageResultEuiccPackageErrorUnsigned(EuiccPackageErrorUnsigned{
		EimId: "eim.example",
	})
	transfer := NewTransferEimPackageResponseEuiccPackageResult(result)

	got, err := transfer.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER() error = %v", err)
	}

	outerTag, content, total, err := ber.DecodeConstructedContent(got)
	if err != nil {
		t.Fatalf("DecodeConstructedContent() error = %v", err)
	}
	if total != len(got) {
		t.Fatalf("outer consumed %d bytes, want %d", total, len(got))
	}
	if outerTag.Class != tag.ClassContextSpecific || outerTag.Number != 78 {
		t.Fatalf("outer tag = %s, want [CONTEXT 78]", outerTag)
	}
	resultTag, resultContent, resultTotal, err := ber.DecodeConstructedContent(content)
	if err != nil {
		t.Fatalf("DecodeConstructedContent(result) error = %v", err)
	}
	if resultTotal != len(content) {
		t.Fatalf("result consumed %d bytes, want %d", resultTotal, len(content))
	}
	if resultTag.Class != tag.ClassContextSpecific || resultTag.Number != 81 {
		t.Fatalf("result tag = %s, want [CONTEXT 81]", resultTag)
	}
	innerTag, err := ber.PeekTag(resultContent)
	if err != nil {
		t.Fatalf("PeekTag(inner) error = %v", err)
	}
	if innerTag.Class != tag.ClassContextSpecific || innerTag.Number != 2 {
		t.Fatalf("inner tag = %s, want EuiccPackageResult alternative [CONTEXT 2]", innerTag)
	}

	var decoded TransferEimPackageResponse
	if err := decoded.UnmarshalBER(got); err != nil {
		t.Fatalf("UnmarshalBER() error = %v", err)
	}
	if decoded.Choice != TransferEimPackageResponseChoiceEuiccPackageResult {
		t.Fatalf("decoded choice = %d, want %d", decoded.Choice, TransferEimPackageResponseChoiceEuiccPackageResult)
	}
	if decoded.EuiccPackageResult == nil ||
		decoded.EuiccPackageResult.Choice != EuiccPackageResultChoiceEuiccPackageErrorUnsigned {
		t.Fatalf("decoded package result = %#v", decoded.EuiccPackageResult)
	}
}

func TestEPRAndNotificationsPreserveEuiccPackageResultChoiceTLV(t *testing.T) {
	result := NewEuiccPackageResultEuiccPackageErrorUnsigned(EuiccPackageErrorUnsigned{
		EimId: "eim.example",
	})

	tests := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{
			name: "EimPackageResult",
			marshal: func() ([]byte, error) {
				return (&EimPackageResultEPRAndNotifications{
					EuiccPackageResult: result,
					NotificationList:   PendingNotificationList{},
				}).MarshalBER()
			},
		},
		{
			name: "TransferEimPackageResponse",
			marshal: func() ([]byte, error) {
				return (&TransferEimPackageResponseEPRAndNotifications{
					EuiccPackageResult: result,
					NotificationList:   PendingNotificationList{},
				}).MarshalBER()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.marshal()
			if err != nil {
				t.Fatalf("MarshalBER() error = %v", err)
			}
			content, total, err := ber.DecodeSequenceContent(encoded)
			if err != nil {
				t.Fatalf("DecodeSequenceContent() error = %v", err)
			}
			if total != len(encoded) {
				t.Fatalf("sequence consumed %d bytes, want %d", total, len(encoded))
			}
			wrapperTag, wrapperContent, _, err := ber.DecodeConstructedContent(content)
			if err != nil {
				t.Fatalf("DecodeConstructedContent(first child) error = %v", err)
			}
			if wrapperTag.Class != tag.ClassContextSpecific || wrapperTag.Number != 81 {
				t.Fatalf("wrapper tag = %s, want [CONTEXT 81]", wrapperTag)
			}
			innerTag, err := ber.PeekTag(wrapperContent)
			if err != nil {
				t.Fatalf("PeekTag(wrapper content) error = %v", err)
			}
			if innerTag.Class != tag.ClassContextSpecific || innerTag.Number != 2 {
				t.Fatalf("inner tag = %s, want EuiccPackageResult alternative [CONTEXT 2]", innerTag)
			}
		})
	}
}

func TestTransferEimPackageRequestDecodesTaggedAlternatives(t *testing.T) {
	tests := []struct {
		name       string
		request    TransferEimPackageRequest
		wantChoice int
	}{
		{
			name:       "euiccPackageRequest",
			request:    NewTransferEimPackageRequestEuiccPackageRequest(minimalEuiccPackageRequest()),
			wantChoice: TransferEimPackageRequestChoiceEuiccPackageRequest,
		},
		{
			name: "ipaEuiccDataRequest",
			request: NewTransferEimPackageRequestIpaEuiccDataRequest(IpaEuiccDataRequest{
				TagList: []byte{},
			}),
			wantChoice: TransferEimPackageRequestChoiceIpaEuiccDataRequest,
		},
		{
			name:       "profileDownloadTriggerRequest",
			request:    NewTransferEimPackageRequestProfileDownloadTriggerRequest(ProfileDownloadTriggerRequest{}),
			wantChoice: TransferEimPackageRequestChoiceProfileDownloadTriggerRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.request.MarshalBER()
			if err != nil {
				t.Fatalf("MarshalBER() error = %v", err)
			}

			var decoded TransferEimPackageRequest
			if err := decoded.UnmarshalBER(encoded); err != nil {
				t.Fatalf("UnmarshalBER() error = %v", err)
			}
			if decoded.Choice != tc.wantChoice {
				t.Fatalf("decoded choice = %d, want %d", decoded.Choice, tc.wantChoice)
			}
		})
	}
}

func minimalEuiccPackageRequest() EuiccPackageRequest {
	return EuiccPackageRequest{
		EuiccPackageSigned: EuiccPackageSigned{
			EimId:        "eim.example",
			EidValue:     sgp22.Octet16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			CounterValue: big.NewInt(1),
			EuiccPackage: NewEuiccPackagePsmoList(EuiccPackagePsmoList{}),
		},
		EimSignature: []byte{},
	}
}
