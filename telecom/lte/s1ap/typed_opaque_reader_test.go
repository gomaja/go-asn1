// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	testing "testing"
)

func TestUnknownIEOpaqueChildReader(t *testing.T) {
	for _, size := range []int{1, 65540} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xab}, size)
			cause := s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().Cause().New(causeFreshMust(s26.NewCauseMisc(s00.CauseMiscUnspecified))))
			opaque := s1SetupFailureIEFieldFreshMust(s23.S1SetupFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, payload))
			body := s1SetupFailureFreshMust(s50.NewS1SetupFailure(s23.S1SetupFailureIEContainer{cause, opaque}))
			message := unsuccessfulOutcomeFreshMust(s53.S1SetupProcedure().Unsuccessful().Build(body))
			pdu := s1APPDUFreshMust(s53.NewS1APPDUUnsuccessfulOutcome(message))
			wire := sliceByteFreshMust(pdu.MarshalAPER())
			var decoded s53.S1APPDU
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
