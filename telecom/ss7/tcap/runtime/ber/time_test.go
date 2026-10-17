// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/time_test.go; SHA-256 a91be237e0bf5ca098699c10a09f5df999d1a814e1fa22faaff16cc1fb66bf5a.
package ber

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func primitiveTime(number int, contents string) []byte {
	return encodeFixedTLV(tag.Tag{Class: tag.ClassUniversal, Number: number}, []byte(contents))
}

// DER accepts only X.690 (02/2021) §11.7/§11.8 forms.
func TestValidateDERTimeForms(t *testing.T) {
	for _, c := range []struct {
		number int
		text   string
		valid  bool
	}{
		{tag.TagUTCTime, "920521000000Z", true},
		{tag.TagUTCTime, "500101000000Z", true},
		{tag.TagUTCTime, "491231235959Z", true},
		{tag.TagUTCTime, "920520240000Z", false}, // §11.8.5
		{tag.TagUTCTime, "9207221321Z", false},   // §11.8.5
		{tag.TagUTCTime, "920722132100+0000", false},
		{tag.TagUTCTime, "920722132100-0000", false},
		{tag.TagGeneralizedTime, "19920521000000Z", true},
		{tag.TagGeneralizedTime, "19920722132100.3Z", true},
		{tag.TagGeneralizedTime, "00000101000000Z", true},
		{tag.TagGeneralizedTime, "19920520240000Z", false},    // §11.7.5
		{tag.TagGeneralizedTime, "19920622123421.0Z", false},  // §11.7.3
		{tag.TagGeneralizedTime, "19920722132100.30Z", false}, // §11.7.3
		{tag.TagGeneralizedTime, "19920722132100,3Z", false},  // §11.7.4
		{tag.TagGeneralizedTime, "199207221321Z", false},      // §11.7.2
		{tag.TagGeneralizedTime, "19920722132100", false},     // §11.7.1
		{tag.TagGeneralizedTime, "19920722132100+0000", false},
		{tag.TagGeneralizedTime, "19920722132100.Z", false},
	} {
		err := ValidateDERElement(primitiveTime(c.number, c.text))
		if (err == nil) != c.valid {
			t.Errorf("%q: %v", c.text, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%q: %v does not wrap ErrInvalidValue", c.text, err)
		}
	}
}
