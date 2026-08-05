package rrc_test

import (
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/rrc"
)

func TestPublicPackageNameAndRestoredModules(t *testing.T) {
	_ = rrc.BCCHBCHMessage{}
	_ = rrc.VarConditionalReconfiguration{}
	_ = rrc.LogMeasInfoList2R10{}
	_ = rrc.SLPreconfigurationR12{}
	_ = rrc.VarANRMeasConfigNBR16{}
	if rrc.MaxLogMeasR10 != 4060 {
		t.Fatalf("MaxLogMeasR10: got %d, want 4060", rrc.MaxLogMeasR10)
	}
}
