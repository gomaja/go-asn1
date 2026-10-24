package lppa

import (
	q10 "bytes"
	q9 "fmt"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	q8 "testing"
)

func TestReplayUnknownIEOpaqueReaders(t *q8.T) {
	for _, size := range []int{1, 65540} {
		t.Run(q9.Sprint(size), func(t *q8.T) {
			payload := q10.Repeat([]byte{0xab}, size)
			field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, payload))
			body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field}}
			message := InitiatingMessage{ProcedureCode: 0, Criticality: CriticalityIgnore, LppatransactionID: 1, Value: func() InitiatingValue {
				sealed := InitiatingValue{}
				*bridge0.BridgeInitiatingValueFieldCode(&sealed) = 0
				*bridge0.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &body
				return sealed
			}()}
			pdu := LPPAPDU{Choice: LPPAPDUChoiceInitiatingMessage, InitiatingMessage: &message}
			wire := sliceByteReplayMust(pdu.MarshalAPER())
			var value LPPAPDU
			if _, err := value.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			selected, ok := value.InitiatingMessage.Value.AsErrorIndication()
			if !ok {
				t.Fatal("lost procedure")
			}
			raw, ok := selected.ProtocolIEs[0].Value.Opaque()
			if !ok {
				t.Fatal("lost opaque value")
			}
			first, second := raw.ChildDecodeBuffer(), raw.ChildDecodeBuffer()
			got, err := first.ReadBytes(size)
			if err != nil || !q10.Equal(got, payload) {
				t.Fatalf("opaque reader: %v", err)
			}
			if second.BitPos() != 0 {
				t.Fatal("shared reader cursor")
			}
			got, err = second.ReadBytes(size)
			if err != nil || !q10.Equal(got, payload) {
				t.Fatal("independent contents differ")
			}
			first.Bytes()[0] ^= 0xff
			if !q10.Equal(raw.Bytes(), payload) {
				t.Fatal("reader exposed immutable input")
			}
			if got := sliceByteReplayMust(value.MarshalAPER()); !q10.Equal(got, wire) {
				t.Fatal("opaque read changed replay")
			}
		})
	}
}
