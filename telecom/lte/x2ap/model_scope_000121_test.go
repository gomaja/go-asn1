// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s04 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s04"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestWithoutReplayNamedListAndGeneric(t *testing.T) {
	item := s04.CriticalityDiagnosticsIEListElem{}
	if err := item.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s04.X2apInternalCriticalityDiagnosticsIEListElemFieldExtCount(&item) = 3
	*s04.X2apInternalCriticalityDiagnosticsIEListElemFieldExtPresent(&item) = append(*s04.X2apInternalCriticalityDiagnosticsIEListElemFieldExtPresent(&item), false, false, false)
	*s04.X2apInternalCriticalityDiagnosticsIEListElemFieldExtData(&item) = append(*s04.X2apInternalCriticalityDiagnosticsIEListElemFieldExtData(&item), nil, nil, nil)
	list := s14.CriticalityDiagnosticsIEListComplete{Value: s06.CriticalityDiagnosticsIEList{item}}
	wire := listByteapiMust(list.MarshalAPER())
	var original s14.CriticalityDiagnosticsIEListComplete
	if _, err := original.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	sibling := original
	copy := original.WithoutReplay()
	got := listByteapiMust(copy.MarshalAPER())
	want := listByteapiMust(original.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(got, want) || bytes.Equal(got, wire) {
		t.Fatalf("named list copy = %x, option = %x, received = %x", got, want, wire)
	}
	for _, v := range []*s14.CriticalityDiagnosticsIEListComplete{&original, &sibling} {
		if !bytes.Equal(listByteapiMust(v.MarshalAPER()), wire) {
			t.Fatal("named list fresh copy changed original or sibling")
		}
	}
	codec := s14.CriticalityDiagnosticsIEListCodec()
	decoded, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	fresh := decoded.WithoutReplay()
	if got, want := listByteapiMust(codec.EncodeAPER(fresh)), listByteapiMust(codec.EncodeAPER(decoded, aper.WithoutReplay())); !bytes.Equal(got, want) {
		t.Fatalf("generic copy = %x, option = %x", got, want)
	}
	if !bytes.Equal(listByteapiMust(codec.EncodeAPER(decoded)), wire) {
		t.Fatal("generic fresh copy changed original")
	}
}
