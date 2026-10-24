// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	testing "testing"
)

func TestExtensionAndPrivateReceivedForms(t *testing.T) {
	cd := s06.CriticalityDiagnostics{IEExtensions: s02.CriticalityDiagnosticsExtIEsExtContainer{criticalityDiagnosticsExtIEsExtFieldapiMust(s06.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))}}
	wire := listByteapiMust(cd.MarshalAPER())
	var decoded s06.CriticalityDiagnostics
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	form := decoded.IEExtensions[0].ReceivedForm()
	if !form.Present() || !form.Location().HasWireLocation || len(form.OriginalBytes()) == 0 {
		t.Fatal("extension received form absent")
	}
	for _, id := range []s00.PrivateIEID{privateIEIDapiMust(s00.NewPrivateIEIDLocal(1)), privateIEIDapiMust(s00.NewPrivateIEIDGlobal(runtime.MustObjectIdentifier("1.2.3")))} {
		message := privateMessageapiMust(s19.NewPrivateMessage(s00.PrivateMessageIEsValuePrivateIEContainer{privateMessageIEsValuePrivateIEFieldapiMust(s00.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0}))}))
		wire := listByteapiMust(message.MarshalAPER())
		var received s19.PrivateMessage
		if _, err := received.UnmarshalAPER(wire); err != nil {
			t.Fatal(err)
		}
		form := received.PrivateIEs[0].ReceivedForm()
		if !form.Present() || !form.Location().HasWireLocation || len(form.OriginalBytes()) == 0 {
			t.Fatal("private received form absent")
		}
		if !bytes.Equal(listByteapiMust(received.MarshalAPER()), wire) {
			t.Fatal("private received field did not replay")
		}
	}
}
