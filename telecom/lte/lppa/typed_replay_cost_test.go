package lppa

import (
	q13 "bytes"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"

	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

func TestReplayDecodeCallsNoEncoder(t *q8.T) {
	c := ReportCharacteristicsCodec()
	encode := *bridge0.BridgeReportCharacteristicsValueCodecFieldEncode(&c)
	calls := 0
	*bridge0.BridgeReportCharacteristicsValueCodecFieldEncode(&c) = func(v ReportCharacteristics, fresh bool, b *q12.DecodeBudget) ([]byte, error) {
		calls++
		return encode(v, fresh, b)
	}
	v, _, err := c.DecodeAPER([]byte{0x40})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("decode called encoder %d times", calls)
	}
	calls = 0
	wire, err := c.EncodeAPER(v)
	if err != nil || !q13.Equal(wire, []byte{0x40}) {
		t.Fatalf("wire=%x err=%v", wire, err)
	}
	if calls != 0 {
		t.Fatalf("unchanged encode called encoder %d times", calls)
	}
}
