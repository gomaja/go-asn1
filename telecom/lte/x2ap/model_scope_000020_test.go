// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

// TestVectorHandoverRequestUeHistoryIe15 verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.1.1.1, 9.2.38, 9.2.39, and 9.2.40; id-UE-HistoryInformation 15.
func TestVectorHandoverRequestUeHistoryIe15(t *testing.T) {
	input := asn1VectorHex(t, "000021f35412345670000005")
	if got := s18.HandoverRequestIEs().ID().Source().Assignment; got != "HandoverRequest-IEs" {
		t.Fatalf("table = %s", got)
	}
	codec := s18.HandoverRequestIEs().UEHistoryInformation().Codec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "[0].Choice", "1")
	asn1VectorAssertPath(t, &decoded.Value, "[0].EUTRANCell.GlobalCellID.PLMNIdentity", "\"IfNU\"")
	asn1VectorAssertPath(t, &decoded.Value, "[0].EUTRANCell.GlobalCellID.EUTRANcellIdentifier.BitLength", "28")
	asn1VectorAssertPath(t, &decoded.Value, "[0].EUTRANCell.CellType.CellSize", "0")
	asn1VectorAssertPath(t, &decoded.Value, "[0].EUTRANCell.TimeUEStayedInCell", "5")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
