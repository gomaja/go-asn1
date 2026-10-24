// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	hex "encoding/hex"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	math "math"
	big "math/big"
	testing "testing"
)

// Complete encodings independently checked against the pinned source model.
func TestSourceScalarOracleEncodings(t *testing.T) {
	rows := []struct {
		name, hex string
		encode    func() []byte
	}{
		{"octets", "03010203", func() []byte {
			return listByteapiMust(s13.X2APMessageCodec().EncodeAPER(x2APMessageAPERValueapiMust(s13.X2APMessageCodec().New([]byte{1, 2, 3}))))
		}},
		{"bits", "0180a0", func() []byte {
			return listByteapiMust(s09.TransportLayerAddressCodec().EncodeAPER(transportLayerAddressAPERValueapiMust(s09.TransportLayerAddressCodec().New(runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}))))
		}},
		{"integer", "80110400000000000000000000000000000000", func() []byte {
			return listByteapiMust(s00.CellCapacityClassValueCodec().EncodeAPER(cellCapacityClassValueAPERValueapiMust(s00.CellCapacityClassValueCodec().New(new(big.Int).Lsh(big.NewInt(1), 130)))))
		}},
		{"disjoint-integer", "1380", func() []byte {
			return listByteapiMust(s00.ExpectedActivityPeriodCodec().EncodeAPER(expectedActivityPeriodAPERValueapiMust(s00.ExpectedActivityPeriodCodec().New(big.NewInt(40)))))
		}},
		{"visible-string", "1668747470733a2f2f7265662e696e76616c69642f7832", func() []byte {
			return listByteapiMust(s16.URIAddressCodec().EncodeAPER(uRIAddressAPERValueapiMust(s16.URIAddressCodec().New("https://ref.invalid/x2"))))
		}},
		{"uint64", "000000000000000000e0ffffffffffffffffe08000000000000000", func() []byte {
			return listByteapiMust(s06.ERABUsageReportItemCodec().EncodeAPER(eRABUsageReportItemAPERValueapiMust(s06.ERABUsageReportItemCodec().New(s04.ERABUsageReportItem{StartTimeStamp: make([]byte, 4), EndTimeStamp: make([]byte, 4), UsageCountUL: math.MaxUint64, UsageCountDL: 1 << 63}))))
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			want, err := hex.DecodeString(row.hex)
			if err != nil {
				t.Fatal(err)
			}
			if got := row.encode(); !bytes.Equal(got, want) {
				t.Fatalf("source encoding=%x want=%x", got, want)
			}
		})
	}
}
