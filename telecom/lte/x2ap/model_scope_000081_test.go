// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// X.691 (02/2021) §§11.1.4, 11.2.1 forbid an empty complete open encoding.
// Validation must refuse the same opaque PDU state that both encoders refuse.
func TestPortEmptyUnknownChoiceValidationParity(t *testing.T) {
	for _, contents := range [][]byte{nil, {}, {0}} {
		var extension aper.ChoiceExtension
		if len(contents) == 0 {
			if _, err := aper.NewChoiceExtension(0, contents); err == nil {
				t.Fatal("empty complete extension constructed")
			}
		} else {
			extension = choiceExtensionapiMust(aper.NewChoiceExtension(0, contents))
		}
		value := s19.X2APPDU{UnknownExtension: &extension}
		for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
			_, encodeErr := value.MarshalAPER(options...)
			report, err := s20.ValidateMessage(&value)
			if (encodeErr != nil) != (err != nil) {
				t.Fatalf("unknown contents length %d: encode=%v validate=%v report=%+v", len(contents), encodeErr, err, report)
			}
		}
	}
}
