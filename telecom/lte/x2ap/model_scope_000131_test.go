// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestUnknownAdditionRestoreReplaysOriginalBitmap(t *testing.T) {
	value := s06.CriticalityDiagnostics{}
	if err := value.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	*s06.X2apInternalCriticalityDiagnosticsFieldExtCount(&value) = 3
	*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&value) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtPresent(&value), false, false, false)
	*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&value) = append(*s06.X2apInternalCriticalityDiagnosticsFieldExtData(&value), nil, nil, nil)
	wire := listByteapiMust(value.MarshalAPER())
	var decoded s06.CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if err := decoded.RemoveExtension(0); err != nil {
		t.Fatal(err)
	}
	if err := decoded.SetExtension(0, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(listByteapiMust(decoded.MarshalAPER()), wire) {
		t.Fatal("restored unknown addition lost received bitmap")
	}
	if bytes.Equal(listByteapiMust(decoded.MarshalAPER(aper.WithoutReplay())), wire) {
		t.Fatal("fixture needs nonpreferred bitmap")
	}
}
