package rrc_test

import (
	"math"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/rrc"
)

func TestChoiceMinimumIndexRejectedBeforeWrite(t *testing.T) {
	value := rrc.PagingUEIdentity{Choice: math.MinInt}
	bb := per.NewBitBuffer()
	if err := value.MarshalUPERTo(bb); err == nil {
		t.Fatal("minimum host-int CHOICE index accepted")
	}
	if bits := bb.BitsWritten(); bits != 0 {
		t.Fatalf("invalid CHOICE wrote %d bits", bits)
	}
}
