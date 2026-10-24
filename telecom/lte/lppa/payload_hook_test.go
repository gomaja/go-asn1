package lppa

import (
	"bytes"

	"testing"
)

func TestPayloadCodecOwnsBytesAndEnforcesBoundary(t *testing.T) {
	if _, err := (NewPayloadCodec[int]{}).Call(nil, func(int, PayloadLimits) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("accepted nil decoder")
	}
	codec, err := (NewPayloadCodec[int]{}).Call(
		func(data []byte, limits PayloadLimits) (int, PayloadReport, error) {
			if limits.MaxInputBytes != 3 {
				t.Errorf("input limit = %d", limits.MaxInputBytes)
			}
			data[0] = 0xff
			return len(data), PayloadReport{}, nil
		},
		func(value int, _ PayloadLimits) ([]byte, error) { return []byte{byte(value)}, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte{1, 2, 3}
	value, _, err := (DecodePayload[int]{}).Call(input, codec, PayloadLimits{MaxInputBytes: 3})
	if err != nil || value != 3 || !bytes.Equal(input, []byte{1, 2, 3}) {
		t.Fatalf("decode value=%d input=%x err=%v", value, input, err)
	}
	if _, _, err := (DecodePayload[int]{}).Call(input, codec, PayloadLimits{MaxInputBytes: 2}); err == nil {
		t.Fatal("accepted payload above input limit")
	}
	wire, err := (EncodePayload[int]{}).Call(3, codec, PayloadLimits{MaxOutputBytes: 1})
	if err != nil || !bytes.Equal(wire, []byte{3}) {
		t.Fatalf("encode wire=%x err=%v", wire, err)
	}
	if _, err := (EncodePayload[int]{}).Call(3, codec, PayloadLimits{MaxOutputBytes: 0}); err != nil {
		t.Fatalf("zero selects defaults: %v", err)
	}
}
