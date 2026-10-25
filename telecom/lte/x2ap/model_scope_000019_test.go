// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

// TestVectorHandoverRequestUeHistoryRecursive verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.1.1.1, 9.2.38, 9.2.39, and 9.2.40; HandoverRequest includes mandatory id-UE-HistoryInformation 15.
func TestVectorHandoverRequestUeHistoryRecursive(t *testing.T) {
	input := asn1VectorHex(t, "0000007b000006000a00020001000540020000000b00080021f35412345670001700070021f354000101000e004100010000000000000000000000000000000000000000000000000000000000000000000000000000010001000004400e4500060401f0c000020100000001020000000f400c000021f35412345670000005")
	codec := s20.X2APPDUCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "InitiatingMessage.Value.AsHandoverRequest.ProtocolIEs[5].Value.AsUEHistoryInformation[0].Choice", "1")
	asn1VectorAssertPath(t, &decoded.Value, "InitiatingMessage.Value.AsHandoverRequest.ProtocolIEs[5].Value.AsUEHistoryInformation[0].EUTRANCell.GlobalCellID.PLMNIdentity", "\"IfNU\"")
	asn1VectorAssertPath(t, &decoded.Value, "InitiatingMessage.Value.AsHandoverRequest.ProtocolIEs[5].Value.AsUEHistoryInformation[0].EUTRANCell.CellType.CellSize", "0")
	asn1VectorAssertPath(t, &decoded.Value, "InitiatingMessage.Value.AsHandoverRequest.ProtocolIEs[5].Value.AsUEHistoryInformation[0].EUTRANCell.TimeUEStayedInCell", "5")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
