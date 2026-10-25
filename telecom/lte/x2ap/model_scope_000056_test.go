// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestIEExtensionAndPrivateSelectors(t *testing.T) {
	field := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().Cause().New(apiCause()))
	field.Id = 17
	bb := aper.NewBitBuffer()
	apiRefused(t, s11.X2apInternalErrorIndicationIEFieldMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Fatal("emitted IE bits")
	}
	body := s20.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field}}
	r, err := s20.ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	apiHas(t, r, s00.ValueIDMismatch)
	extension := traceActivationExtIEsExtFieldapiMust(s16.TraceActivationExtIEs().TraceCollectionEntityURI().New("https://example.invalid/trace"))
	extension.Id++
	bb = aper.NewBitBuffer()
	apiRefused(t, s16.X2apInternalTraceActivationExtIEsExtFieldMarshalAPERTo(&extension, bb))
	if bb.BitPos() != 0 {
		t.Fatal("emitted extension bits")
	}
	trace := s16.TraceActivation{IEExtensions: s16.TraceActivationExtIEsExtContainer{extension}}
	r = s12.ValidationReport{Complete: true}
	s16.X2apInternalWalkValidationTraceActivation(&trace, &r, "TraceActivation", false)
	apiHas(t, r, s00.ValueIDMismatch)
	for _, id := range []s00.PrivateIEID{privateIEIDapiMust(s00.NewPrivateIEIDLocal(1)), privateIEIDapiMust(s00.NewPrivateIEIDGlobal(runtime.MustObjectIdentifier("1.2.3")))} {
		private := privateMessageIEsValuePrivateIEFieldapiMust(s00.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0}))
		original := listByteapiMust(private.Id.MarshalAPER())
		if private.Id.Local != nil {
			*private.Id.Local++
		} else {
			*private.Id.Global = runtime.MustObjectIdentifier("1.2.4")
		}
		bb = aper.NewBitBuffer()
		apiRefused(t, s00.X2apInternalPrivateMessageIEsValuePrivateIEFieldMarshalAPERTo(&private, bb))
		if bb.BitPos() != 0 {
			t.Fatal("emitted private IE bits")
		}
		message := s20.PrivateMessage{PrivateIEs: s00.PrivateMessageIEsValuePrivateIEContainer{private}}
		r, err = s20.ValidatePrivateMessage(&message)
		if err != nil {
			t.Fatal(err)
		}
		apiHas(t, r, s00.ValueIDMismatch)
		if _, err := s20.NewPrivateMessage(message.PrivateIEs); err == nil {
			t.Fatal("private builder accepted mismatch")
		}
		if _, err := private.Id.UnmarshalAPER(original); err != nil {
			t.Fatal(err)
		}
		if _, err := s00.X2apInternalPrivateMessageIEsValueEncode(private.Value); err != nil {
			t.Fatal(err)
		}
	}
	// Empty-table opaque values retain their selector just as typed values do.
	opaque := criticalityDiagnosticsExtIEsExtFieldapiMust(s06.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	opaque.Id--
	bb = aper.NewBitBuffer()
	apiRefused(t, s02.X2apInternalCriticalityDiagnosticsExtIEsExtFieldMarshalAPERTo(&opaque, bb))
	if bb.BitPos() != 0 {
		t.Fatal("emitted opaque extension bits")
	}
}
