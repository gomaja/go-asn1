// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestPayloadBoundaryErrorsAreLocated(t *testing.T) {
	check := func(err, errorKind error) {
		t.Helper()
		var located *aper.DecodeError
		if !errors.Is(err, errorKind) || !errors.As(err, &located) || located.Location.Path == "" || located.Location.HasWireLocation {
			t.Fatalf("payload err=%v location=%+v", err, located)
		}
	}
	_, err := IntNewPayloadCodec(nil, nil)
	check(err, aper.ErrInvalidValue)
	_, _, err = IntDecodePayload([]byte{1}, IntPayloadCodec{}, s00.PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	_, err = IntEncodePayload(1, IntPayloadCodec{}, s00.PayloadLimits{})
	check(err, aper.ErrInvalidValue)
	codec, err := IntNewPayloadCodec(func(data []byte, _ s00.PayloadLimits) (int, s00.PayloadReport, error) {
		return len(data), s00.PayloadReport{Deviations: []s00.PayloadDeviation{{Path: "a"}, {Path: "b"}}}, nil
	}, func(int, s00.PayloadLimits) ([]byte, error) { return []byte{1, 2}, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []s00.PayloadLimits{{MaxInputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}, {MaxReports: 1}} {
		_, _, err = IntDecodePayload([]byte{1, 2}, codec, limits)
		check(err, aper.ErrLimit)
	}
	for _, limits := range []s00.PayloadLimits{{MaxOutputBytes: 1}, {MaxAllocatedBytes: 1}, {MaxWork: 1}} {
		_, err = IntEncodePayload(2, codec, limits)
		check(err, aper.ErrLimit)
	}
}
