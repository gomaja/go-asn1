// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	strings "strings"
	testing "testing"
)

func TestPDUUnusedRootChoiceIndex(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s19.X2APPDU
		report, err := value.UnmarshalAPER([]byte{0x60}, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§11.5.7.1" || !strings.Contains(string(located.Location.Path), "X2APPDU") || len(report.Deviations) != 1 {
			t.Fatalf("unused choice: report=%+v err=%v location=%+v", report, err, located)
		}
	}
}
