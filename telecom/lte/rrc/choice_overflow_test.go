package rrc_test

import (
	"math"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	"github.com/gomaja/go-asn1/telecom/lte/rrc/runtime/uper"
)

func TestChoiceMinimumIndexRejectedBeforeWrite(t *testing.T) {
	value := rrc.PagingUEIdentity{Choice: math.MinInt}
	bb := uper.NewBitBuffer()
	if err := value.MarshalUPERTo(bb); err == nil {
		t.Fatal("minimum host-int CHOICE index accepted")
	}
	if bits := bb.BitsWritten(); bits != 0 {
		t.Fatalf("invalid CHOICE wrote %d bits", bits)
	}
}
