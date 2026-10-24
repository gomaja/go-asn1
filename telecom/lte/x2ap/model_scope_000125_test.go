// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestSemanticEqualityIgnoresMandatorySliceStorage(t *testing.T) {
	c := s13.X2APMessageCodec()
	wire := listByteapiMust(c.EncodeAPER(x2APMessageAPERValueapiMust(c.New([]byte{}))))
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	encoder := *s13.X2apInternalX2APMessageValueCodecFieldEncode(&c)
	*s13.X2apInternalX2APMessageValueCodecFieldEncode(&c) = func(s13.X2APMessage, bool, *aper.DecodeBudget) ([]byte, error) {
		t.Fatal("mandatory nil/empty mismatch")
		return nil, nil
	}
	v.Value = nil
	if !bytes.Equal(listByteapiMust(c.EncodeAPER(v)), wire) {
		t.Fatal("mandatory slice storage changed replay")
	}
	*s13.X2apInternalX2APMessageValueCodecFieldEncode(&c) = encoder
	var decoded s06.CriticalityDiagnostics
	wire = listByteapiMust(decoded.MarshalAPER())
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	decoded.IEExtensions = s02.CriticalityDiagnosticsExtIEsExtContainer{}
	if _, err := decoded.MarshalAPER(); err == nil {
		t.Fatal("optional present empty container replayed as absent")
	}
}
