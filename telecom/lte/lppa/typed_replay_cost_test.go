package lppa

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

func TestReplayDecodeCallsNoEncoder(t *testing.T) {
	c := ReportCharacteristicsCodec()
	encode := *s01.BridgeReportCharacteristicsValueCodecFieldEncode(&c)
	calls := 0
	*s01.BridgeReportCharacteristicsValueCodecFieldEncode(&c) = func(v ReportCharacteristics, fresh bool, b *aper.DecodeBudget) ([]byte, error) {
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
	if err != nil || !bytes.Equal(wire, []byte{0x40}) {
		t.Fatalf("wire=%x err=%v", wire, err)
	}
	if calls != 0 {
		t.Fatalf("unchanged encode called encoder %d times", calls)
	}
}
