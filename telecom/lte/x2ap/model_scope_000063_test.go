// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestChoiceTableSelectorsAndPrimitiveReplay(t *testing.T) {
	field := globalRANNODEIDExtIEFieldapiMust(s08.GlobalRANNODEIDExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	choice := globalRANNODEIDapiMust(s05.NewGlobalRANNODEIDChoiceExtension(field))
	choice.ChoiceExtension.Id--
	_, err := choice.MarshalAPER()
	apiRefused(t, err)
	report := s12.ValidationReport{Complete: true}
	s13.X2apInternalWalkValidationGlobalRANNODEID(&choice, &report, "GlobalRANNODEID", false)
	apiHas(t, report, s00.ValueIDMismatch)
	for _, known := range []uint64{0, 1} {
		if _, err := s00.NewENBIDUnknownExtension(known, []byte{0}); err == nil {
			t.Fatal("known ENB-ID CHOICE arm became opaque")
		}
	}
	codec := s07.X2SetupFailureIEs().TimeToWait().Codec()
	if _, _, err := codec.DecodeAPER([]byte{15}); err == nil {
		t.Fatal("nonzero ENUMERATED padding accepted")
	}
	decoded, _, err := codec.DecodeAPER([]byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(listByteapiMust(codec.EncodeAPER(decoded)), []byte{0}) {
		t.Fatal("primitive padding did not replay")
	}
	decoded.Value = s00.TimeToWait(1)
	if bytes.Equal(listByteapiMust(codec.EncodeAPER(decoded)), []byte{0}) {
		t.Fatal("typed edit replayed stale bytes")
	}
	decoded.Value = s00.TimeToWait(0)
	if !bytes.Equal(listByteapiMust(codec.EncodeAPER(decoded)), []byte{0}) || !bytes.Equal(listByteapiMust(codec.EncodeAPER(decoded, aper.WithoutReplay())), []byte{0}) {
		t.Fatal("primitive restore/fresh policy failed")
	}
	if _, _, err := codec.DecodeAPER([]byte{15, 0}); err == nil {
		t.Fatal("known malformed primitive became opaque")
	}
}
