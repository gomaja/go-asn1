// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestMalformedPrimitiveReportIsLocated(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		_, report, err := s06.TimeToWaitCodec().DecodeAPER([]byte{15}, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path != "TimeToWait" || located.Rule.Clause != "§11.1.4" || len(report.Deviations) != 1 || report.Deviations[0].Location.Path != located.Location.Path || report.Deviations[0].Rule != located.Rule {
			t.Fatalf("primitive report=%+v err=%v location=%+v", report, err, located)
		}
	}
}
