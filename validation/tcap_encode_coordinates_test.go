package validation

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #187: encode records describe the abstract value, so their Offset,
// OctetOffset and ChildIndexes are nil (the Violation documentation). The
// value below keeps a definite length below 128 in long form, which Q.773
// (06/1997) §4.1.1 forbids, and tolerant re-encoding replays and reports it.
func TestTCAPEncodeRecordsCarryNoWireCoordinates(t *testing.T) {
	wire := mustHex(t, "02810101")
	var value tcap.TCInvokeIdSet
	if err := value.UnmarshalBER(wire, tcapber.WithTolerance(&tcapber.ViolationLog{})); err != nil {
		t.Fatalf("tolerant decode = %v", err)
	}
	var log tcapber.ViolationLog
	out, err := value.MarshalBER(tcapber.WithTolerance(&log))
	if err != nil || !bytes.Equal(out, wire) {
		t.Fatalf("tolerant replay = %x, %v; want %x", out, err, wire)
	}
	records := log.Snapshot()
	if len(records) != 1 {
		t.Fatalf("encode records = %+v; want one", records)
	}
	if r := records[0]; r.Constraint != "Q.773 §4.1.1: short-length" || r.Offset != nil || r.OctetOffset != nil || r.ChildIndexes != nil {
		t.Fatalf("encode record = %+v; want short-length with no wire coordinates", r)
	}
}
