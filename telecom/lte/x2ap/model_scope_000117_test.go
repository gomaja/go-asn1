// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	big "math/big"
	testing "testing"
)

func TestCompleteReplayMutableContents(t *testing.T) {
	t.Run("octets", func(t *testing.T) {
		x2APMessagesemanticEditRestore(t, s13.X2APMessageCodec(), []byte{1, 2, 3}, func(v *[]byte) { (*v)[1] = 9 }, func(v *[]byte) { (*v)[1] = 2 })
	})
	t.Run("bits", func(t *testing.T) {
		transportLayerAddresssemanticEditRestore(t, s09.TransportLayerAddressCodec(), runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}, func(v *runtime.BitString) { v.Bytes[0] = 0xb0 }, func(v *runtime.BitString) { v.Bytes[0] = 0xa0 })
	})
	t.Run("bit-length", func(t *testing.T) {
		transportLayerAddresssemanticEditRestore(t, s09.TransportLayerAddressCodec(), runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}, func(v *runtime.BitString) { v.BitLength = 5 }, func(v *runtime.BitString) { v.BitLength = 4 })
	})
	t.Run("integer", func(t *testing.T) {
		n := new(big.Int).Lsh(big.NewInt(1), 130)
		cellCapacityClassValuesemanticEditRestore(t, s00.CellCapacityClassValueCodec(), n, func(v **big.Int) { (*v).Add(*v, big.NewInt(7)) }, func(v **big.Int) { (*v).Sub(*v, big.NewInt(7)) })
	})
	t.Run("disjoint-integer", func(t *testing.T) {
		expectedActivityPeriodsemanticEditRestore(t, s00.ExpectedActivityPeriodCodec(), big.NewInt(40), func(v **big.Int) { (*v).SetInt64(50) }, func(v **big.Int) { (*v).SetInt64(40) })
	})
	t.Run("visible-string", func(t *testing.T) {
		uRIAddresssemanticEditRestore(t, s16.URIAddressCodec(), "https://ref.invalid/x2", func(v *string) { *v = "https://ref.invalid/y2" }, func(v *string) { *v = "https://ref.invalid/x2" })
	})
}
