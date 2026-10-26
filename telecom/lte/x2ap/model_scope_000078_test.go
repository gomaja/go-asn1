// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	testing "testing"
)

// TS 36.423 V19.1.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
// which also covers repeated IEs whose IDs are
// not in the selected object set. Unknown IEs still do not set known-row order.
func TestPortValidationUnknownDuplicates(t *testing.T) {
	table := s07.X2SetupFailureIEs()
	cause := x2SetupFailureIEFieldapiMust(table.Cause().New(causeapiMust(s00.NewCauseMisc(s00.CauseMiscUnspecified))))
	for _, id := range []s00.ProtocolIEID{65532, 0} {
		t.Run(fmt.Sprintf("id-%d", id), func(t *testing.T) {
			unknown := x2SetupFailureIEFieldapiMust(table.NewOpaque(id, s00.CriticalityIgnore, []byte{0}))
			body := s14.X2SetupFailure{ProtocolIEs: s07.X2SetupFailureIEContainer{cause, unknown, unknown}}
			report, err := s14.ValidateX2SetupFailure(&body)
			if err != nil {
				t.Fatal(err)
			}
			portRequireRepeated(t, report, id, "[2]")
			var build *s12.BuildError
			if _, err := s14.NewX2SetupFailure(body.ProtocolIEs); !errors.As(err, &build) {
				t.Errorf("builder accepted duplicate id %d: %v", id, err)
			}
		})
	}
	extension := criticalityDiagnosticsExtIEsExtFieldapiMust(s06.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	value := s06.CriticalityDiagnostics{IEExtensions: s02.CriticalityDiagnosticsExtIEsExtContainer{extension, extension}}
	report := s12.ValidationReport{Complete: true}
	s13.X2apInternalWalkValidationCriticalityDiagnostics(&value, &report, "CriticalityDiagnostics", false)
	portRequireRepeated(t, report, 65532, "[1]")
}
