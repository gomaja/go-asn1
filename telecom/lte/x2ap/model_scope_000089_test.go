// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// X.691 (02/2021) §14.3: an unrecognized extension index is legal.
func TestUnknownEnumerationObservation(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		value, report, err := s06.TimeToWaitCodec().DecodeAPER([]byte{0x80}, options...)
		if err != nil || value.Value != s00.TimeToWait(6) || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("unknown enum value=%v report=%+v err=%v", value.Value, report, err)
		}
		observation := report.Observations[0]
		if observation.Kind != aper.UnknownExtension || observation.Rule.Clause != "§14.3" || !observation.Location.HasWireLocation || observation.Location.Path == "" {
			t.Fatalf("observation=%+v", observation)
		}
		replay, err := s06.TimeToWaitCodec().EncodeAPER(value)
		if err != nil || !bytes.Equal(replay, []byte{0x80}) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
		// CauseRadioNetwork has the known NR addition.
		_, report, err = s00.CauseRadioNetworkCodec().DecodeAPER([]byte{0x80}, options...)
		if err != nil || len(report.Observations) != 0 {
			t.Fatalf("known enum report=%+v err=%v", report, err)
		}
	}
}
