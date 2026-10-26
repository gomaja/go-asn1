// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

func TestUnknownIEOpaqueChildReader(t *testing.T) {
	for _, size := range []int{1, 65540} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xab}, size)
			cause := x2SetupFailureIEFieldapiMust(s07.X2SetupFailureIEs().Cause().New(causeapiMust(s00.NewCauseMisc(s00.CauseMiscUnspecified))))
			opaque := x2SetupFailureIEFieldapiMust(s07.X2SetupFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, payload))
			body := x2SetupFailureapiMust(s14.NewX2SetupFailure(s07.X2SetupFailureIEContainer{cause, opaque}))
			message := unsuccessfulOutcomeapiMust(s20.X2SetupProcedure().Unsuccessful().Build(body))
			pdu := x2APPDUapiMust(s20.NewX2APPDUUnsuccessfulOutcome(message))
			wire := listByteapiMust(pdu.MarshalAPER())
			var decoded s19.X2APPDU
			if _, err := decoded.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			selected, ok := decoded.UnsuccessfulOutcome.Value.AsX2SetupFailure()
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
			if got := listByteapiMust(decoded.MarshalAPER()); !bytes.Equal(got, wire) {
				t.Fatal("reading opaque content changed replay")
			}
		})
	}
}
