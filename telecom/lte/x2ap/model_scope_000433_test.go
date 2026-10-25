// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// The callback counter separates semantic capture from encoding, including
// after caller input reuse and edit/restore (X.691 (02/2021) §§11.1–11.2).
func transportLayerAddresssemanticEditRestore(t *testing.T, c s09.TransportLayerAddressValueCodec, initial s09.TransportLayerAddress, edit, restore func(*s09.TransportLayerAddress)) {
	t.Helper()
	encoder := *s09.X2apInternalTransportLayerAddressValueCodecFieldEncode(&c)
	calls := 0
	*s09.X2apInternalTransportLayerAddressValueCodecFieldEncode(&c) = func(v s09.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		calls++
		return encoder(v, fresh, budget)
	}
	wire := listByteapiMust(c.EncodeAPER(transportLayerAddressAPERValueapiMust(c.New(initial))))
	original := bytes.Clone(wire)
	calls = 0
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("decode called value encoder")
	}
	for i := range wire {
		wire[i] ^= 0xff
	}
	got := listByteapiMust(c.EncodeAPER(v))
	if !bytes.Equal(got, original) || calls != 0 {
		t.Fatal("unchanged encode called encoder or borrowed input")
	}
	got[0] ^= 0xff
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(v)), original) {
		t.Fatal("encode exposed received storage")
	}
	edit(&v.Value)
	got = listByteapiMust(c.EncodeAPER(v))
	want := listByteapiMust(c.EncodeAPER(v, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatal("edit did not reach encoder")
	}
	before := calls
	restore(&v.Value)
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(v)), original) || calls != before {
		t.Fatal("restored encode called value encoder")
	}
}
