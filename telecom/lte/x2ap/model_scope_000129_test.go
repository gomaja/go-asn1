// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestBitStringStorageOutsideValueIsIgnored(t *testing.T) {
	c := s09.TransportLayerAddressCodec()
	encoder := *s09.X2apInternalTransportLayerAddressValueCodecFieldEncode(&c)
	calls := 0
	*s09.X2apInternalTransportLayerAddressValueCodecFieldEncode(&c) = func(v runtime.BitString, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, fresh, budget)
	}
	wire := listByteapiMust(c.EncodeAPER(transportLayerAddressAPERValueapiMust(c.New(runtime.BitString{Bytes: []byte{0xa0}, BitLength: 4}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	v.Value.Bytes[0] |= 0xf
	if got := listByteapiMust(c.EncodeAPER(v)); calls != 0 || !bytes.Equal(got, wire) {
		t.Fatal("unused backing bits called encoder")
	}
	v.Value.Bytes = append(v.Value.Bytes, 0xff)
	if got := listByteapiMust(c.EncodeAPER(v)); calls != 0 || !bytes.Equal(got, wire) {
		t.Fatal("unused backing octets called encoder")
	}
}
