package s1ap_test

import (
	"math"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func TestChoiceMinimumIndexRejectedBeforeWrite(t *testing.T) {
	value := s1ap.S1APPDU{Choice: math.MinInt}
	bb := aper.NewBitBuffer()
	if err := value.MarshalAPERTo(bb); err == nil {
		t.Fatal("minimum host-int CHOICE index accepted")
	}
	if bits := bb.BitsWritten(); bits != 0 {
		t.Fatalf("invalid CHOICE wrote %d bits", bits)
	}
}
