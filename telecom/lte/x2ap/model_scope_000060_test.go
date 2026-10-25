// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReceivedFieldsPreserveSiblingFraming(t *testing.T) {
	// X.691 (02/2021) §§11.9.3.8.1–11.9.3.8.3 require a maximal
	// 16K fragment followed by its final one-octet remainder here.
	payload := bytes.Repeat([]byte{165}, 16385)
	field := []byte{255, 252, 64, 193}
	field = append(field, payload[:16384]...)
	field = append(field, 1, payload[16384])
	cause := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().Cause().New(apiCause()))
	bb := aper.NewBitBuffer()
	if err := s11.X2apInternalErrorIndicationIEFieldMarshalAPERTo(&cause, bb); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{0, 0, 2}, field...)
	wire = append(wire, bb.CompleteBytes()...)
	var body s20.ErrorIndication
	if _, err := body.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	observer, ok := any(&body.ProtocolIEs[0]).(interface{ ReceivedForm() aper.ReceivedForm })
	if !ok {
		t.Fatal("generic field lacks its received-form accessor")
	}
	form := observer.ReceivedForm()
	if !form.Present() || !form.Location().HasWireLocation || !bytes.Equal(form.OriginalBytes(), field) {
		t.Fatal("field received framing lost")
	}
	clone := form.OriginalBytes()
	clone[0] = 0
	if !bytes.Equal(observer.ReceivedForm().OriginalBytes(), field) {
		t.Fatal("field received form borrowed mutable bytes")
	}
	if !bytes.Equal(listByteapiMust(body.MarshalAPER()), wire) {
		t.Fatal("unchanged field fragments did not replay")
	}
	replacement := errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().Cause().New(causeapiMust(s00.NewCauseMisc(s00.CauseMisc(3)))))
	body.ProtocolIEs[1] = replacement
	edited := listByteapiMust(body.MarshalAPER())
	if bytes.Equal(edited, wire) || !bytes.Equal(edited[3:3+len(field)], field) {
		t.Fatal("editing a sibling changed untouched field framing")
	}
	fresh := listByteapiMust(body.MarshalAPER(aper.WithoutReplay()))
	if !bytes.Equal(fresh, edited) {
		t.Fatal("fresh encoding altered opaque contents")
	}
}
