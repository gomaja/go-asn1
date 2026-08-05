package gsm_map

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
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
		EpsAuthenticationSetList: testEPSAuthenticationSetList(),
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

func TestSendAuthenticationInfoResAcceptsAuthenticationSetListOnly(t *testing.T) {
	authSet := testAuthenticationSetList()
	want := SendAuthenticationInfoRes{
		AuthenticationSetList: &authSet,
	}

	input, err := want.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}
	if !bytes.Contains(input, []byte{0xa0}) {
		t.Fatalf("MarshalBER = % x, want authenticationSetList [0]", input)
	}

	var got SendAuthenticationInfoRes
	if err := got.UnmarshalBER(input); err != nil {
		t.Fatalf("UnmarshalBER auth-set-only SendAuthenticationInfoRes: %v", err)
	}
	if got.AuthenticationSetList == nil {
		t.Fatalf("AuthenticationSetList = nil, want tripletList")
	}
	if got.AuthenticationSetList.Choice != AuthenticationSetListChoiceTripletList {
		t.Fatalf("AuthenticationSetList choice = %d, want tripletList", got.AuthenticationSetList.Choice)
	}
	if len(got.AuthenticationSetList.TripletList) != 1 {
		t.Fatalf("TripletList length = %d, want 1", len(got.AuthenticationSetList.TripletList))
	}
	if got.EpsAuthenticationSetList != nil {
		t.Fatalf("EpsAuthenticationSetList = %+v, want nil", got.EpsAuthenticationSetList)
	}

	roundTrip, err := got.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER round-trip: %v", err)
	}
	if !bytes.Equal(roundTrip, input) {
		t.Fatalf("MarshalBER round-trip = % x, want % x", roundTrip, input)
	}
}

func TestSendAuthenticationInfoResAcceptsAuthenticationSetListBeforeEPSAndUEUsage(t *testing.T) {
	authSet := testAuthenticationSetList()
	ueUsageType := UEUsageType{0x09}
	want := SendAuthenticationInfoRes{
		AuthenticationSetList:    &authSet,
		EpsAuthenticationSetList: testEPSAuthenticationSetList(),
		UeUsageType:              &ueUsageType,
	}

	input, err := want.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}

	var got SendAuthenticationInfoRes
	if err := got.UnmarshalBER(input); err != nil {
		t.Fatalf("UnmarshalBER mixed SendAuthenticationInfoRes: %v", err)
	}
	if got.AuthenticationSetList == nil || got.AuthenticationSetList.Choice != AuthenticationSetListChoiceTripletList {
		t.Fatalf("AuthenticationSetList = %+v, want tripletList", got.AuthenticationSetList)
	}
	if len(got.EpsAuthenticationSetList) != 1 {
		t.Fatalf("EpsAuthenticationSetList length = %d, want 1", len(got.EpsAuthenticationSetList))
	}
	if got.UeUsageType == nil || !bytes.Equal(*got.UeUsageType, ueUsageType) {
		t.Fatalf("UeUsageType = % x, want % x", got.UeUsageType, ueUsageType)
	}

	roundTrip, err := got.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER round-trip: %v", err)
	}
	if !bytes.Equal(roundTrip, input) {
		t.Fatalf("MarshalBER round-trip = % x, want % x", roundTrip, input)
	}
}

func TestMAPErrorLocalCodeHelpers(t *testing.T) {
	if got := GSMMAPLocalErrorcodeUnknownSubscriber.String(); got != "unknownSubscriber" {
		t.Fatalf("GSMMAPLocalErrorcodeUnknownSubscriber.String() = %q", got)
	}

	mapErr := NewMAPERRORLocalValueInt64(GSMMAPLocalErrorcodeAbsentSubscriberSM)
	local, ok := mapErr.LocalCode()
	if !ok {
		t.Fatalf("MAPERROR.LocalCode ok = false")
	}
	if local != GSMMAPLocalErrorcodeAbsentSubscriberSM {
		t.Fatalf("MAPERROR.LocalCode = %v, want %v", local, GSMMAPLocalErrorcodeAbsentSubscriberSM)
	}
	if got := local.String(); got != "absentSubscriberSM" {
		t.Fatalf("MAPERROR.LocalCode().String() = %q", got)
	}

	generic := NewErrorCodeLocalValueInt64(int64(GSMMAPLocalErrorcodeSystemFailure))
	code, ok := generic.LocalCode()
	if !ok {
		t.Fatalf("ErrorCode.LocalCode ok = false")
	}
	if code != int64(GSMMAPLocalErrorcodeSystemFailure) {
		t.Fatalf("ErrorCode.LocalCode = %d, want %d", code, GSMMAPLocalErrorcodeSystemFailure)
	}

	tooWide := NewErrorCodeLocalValue(new(big.Int).Lsh(big.NewInt(1), 80))
	if code, ok := tooWide.LocalCode(); ok {
		t.Fatalf("wide ErrorCode.LocalCode = %d, true; want false", code)
	}
}

func TestAllocationRetentionPriorityMarshalBERRejectsNilPriorityLevel(t *testing.T) {
	_, err := (&AllocationRetentionPriority{}).MarshalBER()
	if err == nil {
		t.Fatalf("MarshalBER returned nil error")
	}
	if !strings.Contains(err.Error(), "priority-level") || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("MarshalBER error = %q, want priority-level nil error", err)
	}
}

func testAuthenticationSetList() AuthenticationSetList {
	return NewAuthenticationSetListTripletList(TripletList{
		{
			Rand: []byte{0x01},
			Sres: []byte{0x02},
			Kc:   []byte{0x03},
		},
	})
}

func testEPSAuthenticationSetList() EPSAuthenticationSetList {
	return EPSAuthenticationSetList{
		{
			Rand:  []byte{0x01},
			Xres:  []byte{0x02},
			Autn:  []byte{0x03},
			Kasme: []byte{0x04},
		},
	}
}
