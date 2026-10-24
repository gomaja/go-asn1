package lppa

import (
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"strings"
	"testing"
)

func TestTableSelectedOpenTypeDepth(t *testing.T) {
	wire, _ := hex.DecodeString("00020000010d00000200020001300003000140")
	state := aper.ApplyDecodeOptions()
	var v LPPAPDU
	if err := s23.BridgeLPPAPDUMethodUnmarshalAPERWithOptions(&v, wire, state); err != nil {
		t.Fatal(err)
	}
	if n := state.Usage().MaxOpenTypeDepth; n != 2 {
		t.Fatalf("selected open-type depth=%d want 2", n)
	}
}
func TestReplayUnknownDuplicateIE(t *testing.T) {
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
func TestReplayZeroProcedureBinding(t *testing.T) {
	var b ErrorIndicationInitiatingBinding
	if _, err := b.Build(ErrorIndication{}, 0); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("zero binding=%v want unbound binding error", err)
	}
}
