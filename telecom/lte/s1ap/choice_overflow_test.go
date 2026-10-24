package s1ap_test

import (
	"math"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
)

func TestChoiceMinimumIndexRejectedBeforeWrite(t *testing.T) {
	value := s1ap.S1APPDU{Choice: math.MinInt}
	wire, err := value.MarshalAPER()
	if err == nil {
		t.Fatal("minimum host-int CHOICE index accepted")
	}
	if len(wire) != 0 {
		t.Fatalf("invalid CHOICE published %d octets", len(wire))
	}
}
