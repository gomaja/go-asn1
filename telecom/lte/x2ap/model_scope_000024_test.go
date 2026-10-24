// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

// TestVectorHandoverRequestNineVisitedCells verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.2.38 through 9.2.40; UE-HistoryInformation permits up to 16 visited cells.
func TestVectorHandoverRequestNineVisitedCells(t *testing.T) {
	input := asn1VectorHex(t, "800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062")
	if got := s18.HandoverRequestIEs().ID().Source().Assignment; got != "HandoverRequest-IEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s18.HandoverRequestIEs().UEHistoryInformation().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "[0].EUTRANCell.TimeUEStayedInCell", "5")
	asn1VectorAssertPath(t, &decoded.Value, "[1].EUTRANCell.TimeUEStayedInCell", "2")
	asn1VectorAssertPath(t, &decoded.Value, "[3].EUTRANCell.TimeUEStayedInCell", "18")
	asn1VectorAssertPath(t, &decoded.Value, "[8].EUTRANCell.TimeUEStayedInCell", "98")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
