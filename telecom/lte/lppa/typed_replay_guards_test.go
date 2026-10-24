package lppa

import (
	q9 "encoding/hex"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q16 "strings"
	q8 "testing"
)

func TestTableSelectedOpenTypeDepth(t *q8.T) {
	wire, _ := q9.DecodeString("00020000010d00000200020001300003000140")
	state := q10.ApplyDecodeOptions()
	var v LPPAPDU
	if err := bridge0.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&v, wire, state); err != nil {
		t.Fatal(err)
	}
	if n := state.Usage().MaxOpenTypeDepth; n != 2 {
		t.Fatalf("selected open-type depth=%d want 2", n)
	}
}
func TestReplayUnknownDuplicateIE(t *q8.T) {
	field := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65532, CriticalityIgnore, []byte{0}))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{field, field}}
	report, err := ValidateErrorIndication(&body)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, issue := range report.Issues {
		if issue.Code == RepeatedIE {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("unknown duplicate count=%d want 1: %+v", count, report)
	}
	if _, err := NewErrorIndication(body.ProtocolIEs); err == nil {
		t.Fatal("builder accepted duplicate unknown IE")
	}
}
func TestReplayZeroProcedureBinding(t *q8.T) {
	var b ErrorIndicationInitiatingBinding
	if _, err := b.Build(ErrorIndication{}, 0); err == nil || !q16.Contains(err.Error(), "unbound") {
		t.Fatalf("zero binding=%v want unbound binding error", err)
	}
}
