// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

// TS 36.413 V19.2.0 §§9.3.3 and 9.3.7: the private object set is empty;
// each selected value remains opaque and is reported at its value member.
func TestPrivateIEObservationAndSharedLimits(t *testing.T) {
	id := privateIEIDFreshMust(s26.NewPrivateIEIDLocal(1))
	field := privateMessageIEsValuePrivateIEFieldFreshMust(s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	codec := s26.PrivateMessageIEsValuePrivateFieldTableCodec(s25.PrivateMessageIEs().Table())
	wire := sliceByteFreshMust(codec.EncodeAPER(privateMessageIEsValuePrivateIEFieldAPERValueFreshMust(codec.New(field))))
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		value, report, err := codec.DecodeAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		o := report.Observations[0]
		if o.Kind != aper.UnknownIE || !o.Location.HasWireLocation || !strings.HasSuffix(string(o.Location.Path), "PrivateIEField.Value") {
			t.Fatalf("private observation=%+v", o)
		}
		if out, err := codec.EncodeAPER(value); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("replay=%x err=%v", out, err)
		}
	}
	list := s26.PrivateMessageIEsValuePrivateTableCodec(s25.PrivateMessageIEs().Table(), aper.ListBounds{Lower: 1, Upper: 65535})
	wire = sliceByteFreshMust(list.EncodeAPER(privateMessageIEsValuePrivateIEContainerAPERValueFreshMust(list.New(s25.PrivateMessageIEsValuePrivateIEContainer{field, field}))))
	_, report, err := list.DecodeAPER(wire, aper.WithLimits(aper.Limits{MaxReports: 1}))
	var located *aper.DecodeError
	if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || len(report.Observations) != 1 || !located.Location.HasWireLocation {
		t.Fatalf("report ceiling: report=%+v err=%v", report, err)
	}
	if _, err := s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, nil); !errors.Is(err, aper.ErrInvalidValue) {
		t.Fatalf("empty private open accepted: %v", err)
	}
}
func TestPrivateIDComparisonWorkIsCharged(t *testing.T) {
	oid := objectIdentifierFreshMust(runtime.ParseObjectIdentifier("1.2" + strings.Repeat(".1", 4000)))
	id := privateIEIDFreshMust(s26.NewPrivateIEIDGlobal(oid))
	field := privateMessageIEsValuePrivateIEFieldFreshMust(s25.PrivateMessageIEs().NewOpaque(id, s00.CriticalityIgnore, []byte{0x80}))
	budget := ptrDecodeBudgetFreshMust(aper.NewOperationBudget(aper.Limits{MaxWork: 2048}))
	if s25.BridgePrivateMessageIEsValueMethodMatchesID(field.Value, id, budget) {
		t.Fatal("unbounded OID comparison")
	}
	if err := aper.NewBudgetBuffer(budget).CheckOutput(0); !errors.Is(err, aper.ErrLimit) {
		t.Fatalf("work=%v", err)
	}
}
