// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReplayReplacementAndCopyGraphs(t *testing.T) {
	c := s14.CriticalityDiagnosticsIEListCodec()
	wire := replayListWire(t, 2)
	a, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	a.Value[0] = b.Value[0]
	a.Value[1] = a.Value[0]
	a.Value[0].IEID = 9
	if got, want := listByteapiMust(c.EncodeAPER(a)), listByteapiMust(c.EncodeAPER(a, aper.WithoutReplay())); !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatal("foreign owner or duplicate snapshot hid an edit")
	}
	a.Value[0].IEID = 0
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(a)), wire) {
		t.Fatal("restored replacement did not replay")
	}
	a.Value[0] = a.Value[0].WithoutReplay()
	if got, want := listByteapiMust(c.EncodeAPER(a)), listByteapiMust(c.EncodeAPER(a, aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatal("replacement hid nested fresh marker")
	}
}
