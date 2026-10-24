// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// The sole X2AP table containing ID zero needs selected and opaque controls,
// beside the zero-union refusal (TS 36.423 V19.1.0 §9.3.8).
func TestPortZeroIDSelectedAndOpaqueControls(t *testing.T) {
	var value s09.ERABsAdmittedItem
	if _, err := value.UnmarshalAPER([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	selected := eRABsAdmittedItemIEFieldapiMust(s09.ERABsAdmittedItemIEs().ERABsAdmittedItem().New(value))
	opaque := eRABsAdmittedItemIEFieldapiMust(s09.ERABsAdmittedItemIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0, 0}))
	for _, field := range []s09.ERABsAdmittedItemIEField{selected, opaque} {
		if !s09.X2apInternalERABsAdmittedItemIEValueMatchesID(field.Value, field.Id, nil) {
			t.Fatal("explicit arm did not match its selector")
		}
		bb := aper.NewBitBuffer()
		if err := s09.X2apInternalERABsAdmittedItemIEFieldMarshalAPERTo(&field, bb); err != nil {
			t.Fatal(err)
		}
		wire := bb.CompleteBytes()
		decoded := s09.ERABsAdmittedItemIEField{}
		child := aper.NewBitBufferFromBytes(wire)
		if err := s09.X2apInternalERABsAdmittedItemIEFieldUnmarshalAPERFrom(&decoded, child); err != nil {
			t.Fatal(err)
		}
		out := aper.NewBitBuffer()
		if err := s09.X2apInternalERABsAdmittedItemIEFieldMarshalAPERTo(&decoded, out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.CompleteBytes(), wire) {
			t.Fatal("selected id zero did not replay")
		}
	}
}
