package lppa

import (
	q11 "bytes"
	q10 "encoding/hex"

	q9 "testing"
)

var replayDecodeSink LPPAPDU
var replayEncodeSink []byte

// Synthetic source-derived PDUs; counts were measured against the published
// envelope-plus-recursive decode and envelope-only encode on the same toolchain.
func TestReplayPinnedAllocationBounds(t *q9.T) {
	for _, row := range []struct {
		id, hex        string
		decode, encode float64
	}{
		{"ecid-dispatch/envelope/lppa/capture.pcap:1", "0002000000080000010002000100", 11, 1},
		{"ecid-measurement-id/envelope/lppa/capture.pcap:1", "0002000000080000010002000100", 11, 1},
		{"lppa-61-baseline", "00020000010d00000200020001300003000140", 14, 1},
		{"ecid-measurement-id-dispatch", "0002000000080000010002000100", 11, 1},
		{"ecid-measurement-id-header", "0002000000080000010002000100", 11, 1},
		{"error-indication-empty", "000040000003000000", 3, 1},
		{"ecid-initiation-initiating-typed-dispatch", "000200000003000000", 3, 1},
		{"ecid-initiation-successful-typed-dispatch", "200200000003000000", 3, 1},
		{"ecid-initiation-unsuccessful-typed-dispatch", "400200000003000000", 3, 1},
		{"ecid-failure-indication-initiating-typed-dispatch", "000340000003000000", 3, 1},
		{"ecid-report-initiating-typed-dispatch", "000440000003000000", 3, 1},
		{"ecid-termination-initiating-typed-dispatch", "000500000003000000", 3, 1},
		{"otdoa-exchange-initiating-typed-dispatch", "000600000003000000", 3, 1},
		{"otdoa-exchange-successful-typed-dispatch", "200600000003000000", 3, 1},
		{"otdoa-exchange-unsuccessful-typed-dispatch", "400600000003000000", 3, 1},
		{"utdoa-exchange-initiating-typed-dispatch", "000700000003000000", 3, 1},
		{"utdoa-exchange-successful-typed-dispatch", "200700000003000000", 3, 1},
		{"utdoa-exchange-unsuccessful-typed-dispatch", "400700000003000000", 3, 1},
		{"utdoa-update-initiating-typed-dispatch", "000840000003000000", 3, 1},
		{"assistance-control-initiating-typed-dispatch", "000900000003000000", 3, 1},
		{"assistance-feedback-initiating-typed-dispatch", "000a00000003000000", 3, 1},
		{"error-indication-initiating-typed-dispatch", "000040000003000000", 3, 1},
		{"private-message-initiating-typed-dispatch", "000140000009000000000001400100", 6, 1},
	} {
		t.Run(row.id, func(t *q9.T) {
			wire, err := q10.DecodeString(row.hex)
			if err != nil {
				t.Fatal(err)
			}
			var value LPPAPDU
			if _, err := value.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			decode := q9.AllocsPerRun(50, func() {
				var value LPPAPDU
				if _, err := value.UnmarshalAPER(wire); err != nil {
					panic(err)
				}
				replayDecodeSink = value
			})
			encode := q9.AllocsPerRun(50, func() {
				got, err := value.MarshalAPER()
				if err != nil || !q11.Equal(got, wire) {
					panic("unchanged replay")
				}
				replayEncodeSink = got
			})
			t.Logf("decode=%.0f upper=%.0f encode=%.0f upper=%.0f", decode, row.decode, encode, row.encode)
			if decode > row.decode || encode > row.encode {
				t.Fatalf("allocations decode=%.0f/%.0f encode=%.0f/%.0f", decode, row.decode, encode, row.encode)
			}
		})
	}
}
