// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

// X.691 (02/2021) §30.5.3 limits ENBname to the intrinsic PrintableString set.
func TestIntrinsicPrintableAlphabet(t *testing.T) {
	codec := s44.S1SetupRequestIEs().ENBname().Codec()
	for _, symbol := range []byte{'@', '_', 0, 0x1f, 0x7f, 0xff} {
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			_, report, err := codec.DecodeAPER([]byte{0, 0, symbol}, options...)
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§30.5.3" || located.Location.Path == "" || len(report.Deviations) != 1 || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (aper.BitSpan{Start: 16, End: 24}) {
				t.Fatalf("symbol=%x report=%+v error=%v location=%+v", symbol, report, err, located)
			}
		}
	}
	for _, symbol := range []byte{'A', ' ', '?', '+', '=', '9'} {
		if _, _, err := codec.DecodeAPER([]byte{0, 0, symbol}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := codec.New("@"); !errors.Is(err, aper.ErrConstraintViolation) {
		t.Fatalf("source-invalid name built: %v", err)
	}

}

// TS 36.413 V19.2.0 §9.3.4: only the selected TargetID alternative is present.
func TestValidationSkipsInactiveAggregateChoiceArm(t *testing.T) {
	field, err := s11.TargetRNCIDExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	inactive := s34.TargetRNCID{IEExtensions: s11.TargetRNCIDExtIEsExtContainer{field}}
	value := s34.TargetID{Choice: s00.TargetIDChoiceCGI, CGI: &s14.CGI{}, TargetRNCID: &inactive}
	report := s21.ValidationReport{Complete: true}
	s50.BridgeWalkValidationTargetID(&value, &report, "TargetID", false)
	if len(report.Issues) != 0 || len(report.Unchecked) != 0 || !report.Complete {
		t.Fatalf("inactive arm was validated: %+v", report)
	}
	control := s21.ValidationReport{Complete: true}
	s50.BridgeWalkValidationTargetRNCID(&inactive, &control, "TargetRNCID", false)
	if len(control.Issues) == 0 {
		t.Fatal("negative control did not detect the stale arm's invalid table")
	}
}

// TS 36.413 V19.2.0 §9.3.4: URI-Address uses the intrinsic VisibleString set.
// X.691 (02/2021) §30.5.3 excludes control and non-ISO-646 characters.
func TestIntrinsicVisibleAlphabet(t *testing.T) {
	codec := s48.TraceActivationExtIEs().TraceCollectionEntityURI().Codec()
	for _, symbol := range []byte{0, 0x1f, 0x7f, 0xff} {
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			_, report, err := codec.DecodeAPER([]byte{1, symbol}, options...)
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§30.5.3" || located.Location.Path == "" || len(report.Deviations) != 1 || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (aper.BitSpan{Start: 8, End: 16}) {
				t.Fatalf("symbol=%x report=%+v error=%v location=%+v", symbol, report, err, located)
			}
		}
	}
	for _, symbol := range []byte{'@', '_', '~', ' ', '?', 'A'} {
		if _, _, err := codec.DecodeAPER([]byte{1, symbol}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := codec.New("\x1f"); !errors.Is(err, aper.ErrConstraintViolation) {
		t.Fatalf("source-invalid URI built: %v", err)
	}
}
