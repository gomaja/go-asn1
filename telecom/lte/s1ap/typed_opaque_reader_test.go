// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	testing "testing"
)

func TestUnknownIEOpaqueChildReader(t *testing.T) {
	for _, size := range []int{1, 65540} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xab}, size)
			cause := s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().Cause().New(causeFreshMust(s25.NewCauseMisc(s00.CauseMiscUnspecified))))
			opaque := s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, payload))
			body := s1SetupFailureFreshMust(s49.NewS1SetupFailure(s23.S1SetupFailureIEContainer{cause, opaque}))
			message := unsuccessfulOutcomeFreshMust(s52.S1SetupProcedure().Unsuccessful().Build(body))
			pdu := s1APPDUFreshMust(s52.NewS1APPDUUnsuccessfulOutcome(message))
			wire := sliceByteFreshMust(pdu.MarshalAPER())
			var decoded s52.S1APPDU
			if _, err := decoded.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			selected, ok := decoded.UnsuccessfulOutcome.Value.AsS1SetupFailure()
			if !ok {
				t.Fatal("wrong procedure")
			}
			raw, ok := selected.ProtocolIEs[1].Value.Opaque()
			if !ok || !bytes.Equal(raw.Bytes(), payload) {
				t.Fatal("unknown IE contents differ")
			}
			first, second := raw.ChildDecodeBuffer(), raw.ChildDecodeBuffer()
			got, err := first.ReadBytes(size)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("Opaque child reader: %v", err)
			}
			if second.BitPos() != 0 {
				t.Fatal("opaque child cursors are shared")
			}
			got, err = second.ReadBytes(size)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("second Opaque child reader: %v", err)
			}
			if got := sliceByteFreshMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
				t.Fatal("reading opaque content changed replay")
			}
		})
	}
}
