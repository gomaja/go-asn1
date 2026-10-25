// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestAllOutcomeSelectors(t *testing.T) {
	failure := x2SetupFailureapiMust(s14.NewX2SetupFailure(s07.X2SetupFailureIEContainer{x2SetupFailureIEFieldapiMust(s07.X2SetupFailureIEs().Cause().New(apiCause()))}))
	for _, opaque := range []bool{false, true} {
		initiating := initiatingMessageapiMust(s20.ErrorIndicationProcedure().Initiating().Build(s20.ErrorIndication{}))
		successful := successfulOutcomeapiMust(s20.ResetProcedure().Successful().Build(s19.ResetResponse{}))
		unsuccessful := unsuccessfulOutcomeapiMust(s21.X2SetupProcedure().Unsuccessful().Build(failure))
		if opaque {
			initiating = initiatingMessageapiMust(s20.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0}))
			successful = successfulOutcomeapiMust(s19.NewOpaqueSuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
			unsuccessful = unsuccessfulOutcomeapiMust(s14.NewOpaqueUnsuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
		}
		t.Run("initiating", func(t *testing.T) {
			wire := listByteapiMust(initiating.MarshalAPER())
			var received s20.InitiatingMessage
			if _, err := received.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			for _, v := range []s20.InitiatingMessage{initiating, received} {
				original := v.ProcedureCode
				v.ProcedureCode++
				bb := aper.NewBitBuffer()
				apiRefused(t, s20.X2apInternalInitiatingMessageMarshalAPERTo(&v, bb))
				if bb.BitPos() != 0 {
					t.Fatal("emitted envelope bits before selector refusal")
				}
				for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
					_, err := v.MarshalAPER(options...)
					apiRefused(t, err)
				}
				pdu := s20.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &v}
				r, err := s21.ValidateMessage(&pdu)
				if err != nil {
					t.Fatal(err)
				}
				apiHas(t, r, s00.ValueIDMismatch)
				_, err = s21.NewX2APPDUInitiatingMessage(v)
				var build *s12.BuildError
				if !errors.As(err, &build) {
					t.Fatal("PDU builder accepted selector mismatch")
				}
				v.ProcedureCode = original
				if !bytes.Equal(listByteapiMust(v.MarshalAPER()), wire) {
					t.Fatal("restored selector lost replay")
				}
			}
		})
		t.Run("successful", func(t *testing.T) {
			wire := listByteapiMust(successful.MarshalAPER())
			var received s19.SuccessfulOutcome
			if _, err := received.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			for _, v := range []s19.SuccessfulOutcome{successful, received} {
				original := v.ProcedureCode
				v.ProcedureCode++
				bb := aper.NewBitBuffer()
				apiRefused(t, s19.X2apInternalSuccessfulOutcomeMarshalAPERTo(&v, bb))
				if bb.BitPos() != 0 {
					t.Fatal("emitted envelope bits before selector refusal")
				}
				for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
					_, err := v.MarshalAPER(options...)
					apiRefused(t, err)
				}
				pdu := s20.X2APPDU{Choice: s00.X2APPDUChoiceSuccessfulOutcome, SuccessfulOutcome: &v}
				r, err := s21.ValidateMessage(&pdu)
				if err != nil {
					t.Fatal(err)
				}
				apiHas(t, r, s00.ValueIDMismatch)
				_, err = s21.NewX2APPDUSuccessfulOutcome(v)
				var build *s12.BuildError
				if !errors.As(err, &build) {
					t.Fatal("PDU builder accepted selector mismatch")
				}
				v.ProcedureCode = original
				if !bytes.Equal(listByteapiMust(v.MarshalAPER()), wire) {
					t.Fatal("restored selector lost replay")
				}
			}
		})
		t.Run("unsuccessful", func(t *testing.T) {
			wire := listByteapiMust(unsuccessful.MarshalAPER())
			var received s14.UnsuccessfulOutcome
			if _, err := received.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			for _, v := range []s14.UnsuccessfulOutcome{unsuccessful, received} {
				original := v.ProcedureCode
				v.ProcedureCode++
				bb := aper.NewBitBuffer()
				apiRefused(t, s14.X2apInternalUnsuccessfulOutcomeMarshalAPERTo(&v, bb))
				if bb.BitPos() != 0 {
					t.Fatal("emitted envelope bits before selector refusal")
				}
				for _, options := range [][]aper.EncodeOption{nil, {aper.WithoutReplay()}} {
					_, err := v.MarshalAPER(options...)
					apiRefused(t, err)
				}
				pdu := s20.X2APPDU{Choice: s00.X2APPDUChoiceUnsuccessfulOutcome, UnsuccessfulOutcome: &v}
				r, err := s21.ValidateMessage(&pdu)
				if err != nil {
					t.Fatal(err)
				}
				apiHas(t, r, s00.ValueIDMismatch)
				_, err = s21.NewX2APPDUUnsuccessfulOutcome(v)
				var build *s12.BuildError
				if !errors.As(err, &build) {
					t.Fatal("PDU builder accepted selector mismatch")
				}
				v.ProcedureCode = original
				if !bytes.Equal(listByteapiMust(v.MarshalAPER()), wire) {
					t.Fatal("restored selector lost replay")
				}
			}
		})
	}
}
