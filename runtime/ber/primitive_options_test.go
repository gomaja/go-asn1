package ber

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestPrimitiveImplicitDecodersValidateOptions(t *testing.T) {
	var reports ViolationLog
	cases := []struct {
		name    string
		options []DecodeOption
	}{
		{"default", nil}, {"nil", []DecodeOption{nil}},
		{"depth", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: -1})}},
		{"elements", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxElements: -1})}},
		{"work", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: -1})}},
		{"real digits", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: -1})}},
		{"bad path", ChildDecodeOptions(nil, "bad.path")},
		{"empty path", ChildDecodeOptions(nil, "")},
		{"nil report", []DecodeOption{WithConstraintTolerance(nil)}},
		{"duplicate tolerance", []DecodeOption{WithConstraintTolerance(&reports), WithConstraintTolerance(&reports)}},
		{"restored limits", []DecodeOption{WithDecodeLimits(DecodeLimits{MaxWork: -1}), WithDecodeLimits(DecodeLimits{MaxWork: 4096})}},
		{"tolerant", []DecodeOption{WithConstraintTolerance(&reports)}},
		{"child", ChildDecodeOptions(nil, "field")},
	}
	decoders := []struct {
		name     string
		contents []byte
		decode   func(bool, []byte, []DecodeOption) error
	}{
		{"octets", []byte{0xff}, func(c bool, v []byte, o []DecodeOption) error {
			_, err := DecodeImplicitOctetStringValue(c, v, o...)
			return err
		}},
		{"string", []byte("hello"), func(c bool, v []byte, o []DecodeOption) error {
			_, err := DecodeImplicitStringValue(tag.TagUTF8String, c, v, o...)
			return err
		}},
		{"UTC", []byte("260101000000Z"), func(c bool, v []byte, o []DecodeOption) error {
			_, err := DecodeImplicitUTCTimeValue(c, v, o...)
			return err
		}},
		{"generalized", []byte("20260101000000Z"), func(c bool, v []byte, o []DecodeOption) error {
			_, err := DecodeImplicitGeneralizedTimeValue(c, v, o...)
			return err
		}},
	}
	for _, decoder := range decoders {
		for _, test := range cases {
			for _, constructed := range []bool{false, true} {
				t.Run(decoder.name+"/"+test.name+"/"+map[bool]string{false: "primitive", true: "constructed"}[constructed], func(t *testing.T) {
					contents := decoder.contents
					if constructed {
						contents = mustEncode(t)(EncodeOctetString(contents))
					}
					before := bytes.Clone(contents)
					want := ValidateDecodeOptions(test.options...)
					got := decoder.decode(constructed, contents, test.options)
					if (want == nil) != (got == nil) || want != nil && (want.Error() != got.Error() || !errors.Is(got, ErrInvalidValue)) {
						t.Fatalf("got %v, validator %v", got, want)
					}
					if !bytes.Equal(contents, before) {
						t.Fatal("input changed")
					}
					if want != nil {
						// Option rejection precedes even an empty or malformed contents value.
						got = decoder.decode(constructed, nil, test.options)
						if got == nil || got.Error() != want.Error() {
							t.Fatalf("option precedence: %v want %v", got, want)
						}
					}
				})
			}
		}
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("option validation published reports")
	}
}
