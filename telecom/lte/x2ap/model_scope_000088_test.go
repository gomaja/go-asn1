// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	sync "sync"
	testing "testing"
)

func TestGeneratedReceiverOptionsSharedAcrossCalls(t *testing.T) {
	wire := receiverUnknownWire(t, 8)
	options := []aper.DecodeOption{aper.WithReceiverMode(), aper.WithLimits(aper.DefaultLimits())}
	codec := s19.X2APPDUCodec()
	encodeOptions := []aper.EncodeOption{aper.WithEncodeLimits(aper.DefaultLimits())}
	validationOptions := []aper.ValidationOption{aper.WithValidationLimits(aper.DefaultLimits())}
	buildOptions := []aper.BuildOption{aper.WithBuildLimits(aper.DefaultLimits())}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 20 {
				value, report, err := codec.DecodeAPER(wire, options...)
				if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 8 {
					t.Errorf("shared options report=%+v err=%v", report, err)
					return
				}
				replay, err := codec.EncodeAPER(value, encodeOptions...)
				if err != nil || !bytes.Equal(replay, wire) {
					t.Errorf("shared options replay=%x err=%v", replay, err)
					return
				}
				if _, err := s20.ValidateMessage(&value.Value, validationOptions...); err != nil {
					t.Error(err)
					return
				}
				if _, err := s20.NewX2APPDUInitiatingMessage(*value.Value.InitiatingMessage, buildOptions...); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
}
