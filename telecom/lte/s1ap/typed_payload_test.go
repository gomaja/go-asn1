// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	testing "testing"
)

func TestPayloadCodecOwnsBytesAndEnforcesBoundary(t *testing.T) {
	if _, err := (s51.NewPayloadCodec[int]{}).Call(nil, func(int, s00.PayloadLimits) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("accepted nil decoder")
	}
	codec, err := (s51.NewPayloadCodec[int]{}).Call(
		func(data []byte, limits s00.PayloadLimits) (int, s00.PayloadReport, error) {
			if limits.MaxInputBytes != 3 {
				t.Errorf("input limit = %d", limits.MaxInputBytes)
			}
			data[0] = 0xff
			return len(data), s00.PayloadReport{}, nil
		},
		func(value int, _ s00.PayloadLimits) ([]byte, error) { return []byte{byte(value)}, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte{1, 2, 3}
	value, _, err := (s51.DecodePayload[int]{}).Call(input, codec, s00.PayloadLimits{MaxInputBytes: 3})
	if err != nil || value != 3 || !bytes.Equal(input, []byte{1, 2, 3}) {
		t.Fatalf("decode value=%d input=%x err=%v", value, input, err)
	}
	if _, _, err := (s51.DecodePayload[int]{}).Call(input, codec, s00.PayloadLimits{MaxInputBytes: 2}); err == nil {
		t.Fatal("accepted payload above input limit")
	}
	wire, err := (s51.EncodePayload[int]{}).Call(3, codec, s00.PayloadLimits{MaxOutputBytes: 1})
	if err != nil || !bytes.Equal(wire, []byte{3}) {
		t.Fatalf("encode wire=%x err=%v", wire, err)
	}
	if _, err := (s51.EncodePayload[int]{}).Call(3, codec, s00.PayloadLimits{MaxOutputBytes: 0}); err != nil {
		t.Fatalf("zero selects defaults: %v", err)
	}
}
