package validation

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
)

// fuzzRoleCodec checks that a standalone decoder either rejects data or
// yields a value that replays data exactly, and whose DER decodes strictly
// to the same value. Editing a non-canonical decoded holder must produce
// the same BER and DER as a fresh holder of the replacement value.
func fuzzRoleCodec[T any](t *testing.T, data []byte, first, second T,
	decode func([]byte, ...ber.DecodeOption) (*gsm_map.BERValue[T], error),
	encode func(*gsm_map.BERValue[T], ...ber.EncodeOption) ([]byte, error),
	der func(*gsm_map.BERValue[T]) ([]byte, error),
) {
	decoded, err := decode(data)
	if err != nil {
		return
	}
	if replay, err := encode(decoded); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T replay = %x, %v; want %x", decoded.Value, replay, err, data)
	}
	canonical, err := der(decoded)
	if err != nil {
		t.Fatalf("%T DER: %v", decoded.Value, err)
	}
	again, err := decode(canonical)
	if err != nil || !reflect.DeepEqual(again.Value, decoded.Value) {
		t.Fatalf("%T DER %x decodes to %#v, %v", decoded.Value, canonical, again, err)
	}

	// All ten role types have one-octet tags. Add a length octet to make a
	// valid nonminimal BER form (X.690 (02/2021) §8.1.3.5).
	var long []byte
	if canonical[1] < 0x80 {
		long = append([]byte{canonical[0], 0x81}, canonical[1:]...)
	} else {
		long = append([]byte{canonical[0], canonical[1] + 1, 0}, canonical[2:]...)
	}
	edited, err := decode(long)
	if err != nil {
		t.Fatalf("%T long-form decode: %v", decoded.Value, err)
	}
	replacement := first
	if reflect.DeepEqual(edited.Value, first) {
		replacement = second
	}
	if reflect.DeepEqual(edited.Value, replacement) {
		t.Fatal("edit must change Value")
	}
	fresh := &gsm_map.BERValue[T]{Value: replacement}
	want, err := der(fresh)
	if err != nil {
		t.Fatalf("%T fresh DER: %v", replacement, err)
	}
	if encoded, err := encode(fresh); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T fresh BER = %x, %v; want %x", replacement, encoded, err, want)
	}
	edited.Value = replacement
	if encoded, err := encode(edited); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T edited BER = %x, %v; want %x", replacement, encoded, err, want)
	}
	if encoded, err := der(edited); err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("%T edited DER = %x, %v; want %x", replacement, encoded, err, want)
	}
}

// fuzzExtensibleSequence checks the strict and tolerant decoders of an
// extensible SEQUENCE: whatever either accepts replays exactly, a strict
// success reports no violation under tolerance. Tag-order tolerance admission
// is checked separately by TestNotifySSArgComponentOrder.
func fuzzExtensibleSequence(t *testing.T, data []byte, fresh func() berValue) {
	strict := fresh()
	strictErr := strict.UnmarshalBER(data)
	if strictErr == nil {
		if replay, err := strict.MarshalBER(); err != nil || !bytes.Equal(replay, data) {
			t.Fatalf("%T strict replay = %x, %v; want %x", strict, replay, err, data)
		}
	}
	var log ber.ViolationLog
	option := ber.WithConstraintTolerance(&log)
	tolerant := fresh()
	if err := tolerant.UnmarshalBER(data, option); err != nil {
		if strictErr == nil {
			t.Fatalf("%T tolerant rejected a strict value: %v", tolerant, err)
		}
		return
	}
	if strictErr == nil && len(log.Snapshot()) != 0 {
		t.Fatalf("%T strict value reported %+v", tolerant, log.Snapshot())
	}
	if replay, err := tolerant.MarshalBER(option); err != nil || !bytes.Equal(replay, data) {
		t.Fatalf("%T tolerant replay = %x, %v; want %x", tolerant, replay, err, data)
	}
}

func FuzzMAPRoleTypeDecoders(f *testing.F) {
	for _, seed := range []string{
		"0402911f", "0403214365", "040192", "040105", "04010c", "120430303030", "0a0100", "160141",
		"048102911f", "048103214365", "04810192", "04810105", "0481010c", "12810430303030", "0a810100", "16810141",
		"120420303030",
	} {
		f.Add(mustHexF(f, seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoleCodec(t, data, gsm_map.ISDNAddressString{0x91, 0x1f}, gsm_map.ISDNAddressString{0x91, 0x2f}, gsm_map.UnmarshalBERISDNAddressString, gsm_map.MarshalBERISDNAddressString, gsm_map.MarshalDERISDNAddressString)
		fuzzRoleCodec(t, data, gsm_map.IMSI{0x21, 0x43, 0x65}, gsm_map.IMSI{0x65, 0x87, 0x21}, gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI)
		fuzzRoleCodec(t, data, gsm_map.SSCode{0x92}, gsm_map.SSCode{0x93}, gsm_map.UnmarshalBERSSCode, gsm_map.MarshalBERSSCode, gsm_map.MarshalDERSSCode)
		fuzzRoleCodec(t, data, gsm_map.Password("0000"), gsm_map.Password("1234"), gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword)
		fuzzRoleCodec(t, data, gsm_map.GuidanceInfoEnterPW, gsm_map.GuidanceInfoEnterNewPW, gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo)
		fuzzRoleCodec(t, data, gsm_map.SSUserData("A"), gsm_map.SSUserData("B"), gsm_map.UnmarshalBERSSUserData, gsm_map.MarshalBERSSUserData, gsm_map.MarshalDERSSUserData)
		fuzzRoleCodec(t, data, gsm_map.SSStatus{0x05}, gsm_map.SSStatus{0x0a}, gsm_map.UnmarshalBERSSStatus, gsm_map.MarshalBERSSStatus, gsm_map.MarshalDERSSStatus)
		fuzzRoleCodec(t, data, gsm_map.PWRegistrationFailureCauseUndetermined, gsm_map.PWRegistrationFailureCauseInvalidFormat, gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause, gsm_map.MarshalDERPWRegistrationFailureCause)
		fuzzRoleCodec(t, data, gsm_map.SSStatus3{0x0c}, gsm_map.SSStatus3{0x03}, gsm_map.UnmarshalBERSSStatus3, gsm_map.MarshalBERSSStatus3, gsm_map.MarshalDERSSStatus3)
		fuzzRoleCodec(t, data, gsm_map.PWRegistrationFailureCause3Undetermined, gsm_map.PWRegistrationFailureCause3InvalidFormat, gsm_map.UnmarshalBERPWRegistrationFailureCause3, gsm_map.MarshalBERPWRegistrationFailureCause3, gsm_map.MarshalDERPWRegistrationFailureCause3)
	})
}

func FuzzMAPExtensionTail(f *testing.F) {
	for _, seed := range []string{
		"3003810100", "3006810100840100", "3006840100810100", "3006810100810101", "3009850101810100840100",
		"3008a306040400000000", "3005a303800100",
		"301b8000810083008401008600850087008b008800890207808a008c00",
		"3010800192a1053003840101820420303030",
	} {
		f.Add(mustHexF(f, seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzExtensibleSequence(t, data, func() berValue { return &gsm_map.NotifySSArg{} })
		fuzzExtensibleSequence(t, data, func() berValue { return &gsm_map.SingleRelativeResult{} })
		fuzzExtensibleSequence(t, data, func() berValue { return &gsm_map.RequestedInfo6{} })
		fuzzExtensibleSequence(t, data, func() berValue { return &gsm_map.ExtCallBarringInfoForCSE{} })
	})
}

func mustHexF(f *testing.F, text string) []byte {
	f.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		f.Fatal(err)
	}
	return data
}
