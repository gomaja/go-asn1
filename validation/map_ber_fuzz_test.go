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
// to the same value.
func fuzzRoleCodec[T any](t *testing.T, data []byte,
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
}

// fuzzExtensibleSequence checks the strict and tolerant decoders of an
// extensible SEQUENCE: whatever either accepts replays exactly, a strict
// success reports no violation under tolerance, and a value the strict
// decoder rejects only for its first unknown tag is accepted by tolerance.
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
	for _, seed := range []string{"040100", "0403000000", "120430303030", "0a0100", "160141", "04810100", "120420303030"} {
		f.Add(mustHexF(f, seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERISDNAddressString, gsm_map.MarshalBERISDNAddressString, gsm_map.MarshalDERISDNAddressString)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERIMSI, gsm_map.MarshalBERIMSI, gsm_map.MarshalDERIMSI)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERSSCode, gsm_map.MarshalBERSSCode, gsm_map.MarshalDERSSCode)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERPassword, gsm_map.MarshalBERPassword, gsm_map.MarshalDERPassword)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERGuidanceInfo, gsm_map.MarshalBERGuidanceInfo, gsm_map.MarshalDERGuidanceInfo)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERSSUserData, gsm_map.MarshalBERSSUserData, gsm_map.MarshalDERSSUserData)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERSSStatus, gsm_map.MarshalBERSSStatus, gsm_map.MarshalDERSSStatus)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERPWRegistrationFailureCause, gsm_map.MarshalBERPWRegistrationFailureCause, gsm_map.MarshalDERPWRegistrationFailureCause)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERSSStatus3, gsm_map.MarshalBERSSStatus3, gsm_map.MarshalDERSSStatus3)
		fuzzRoleCodec(t, data, gsm_map.UnmarshalBERPWRegistrationFailureCause3, gsm_map.MarshalBERPWRegistrationFailureCause3, gsm_map.MarshalDERPWRegistrationFailureCause3)
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
