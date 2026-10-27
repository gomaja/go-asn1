package validation

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	"github.com/gomaja/go-asn1/telecom/lte/rrc/runtime/uper"
)

// A synthetic UL-DCCH UEInformationResponse-r9 (test PLMN 001-01, invented
// values) whose RLF-Report-r9 carries the v1250 extension addition group,
// whose open type starts at bit 118. In the incomplete input the group's
// length determinant declares one octet, one octet short of
// measResultLastServCell-v1250; the cut input is the complete PDU ending
// inside that open type. Both records locate the same addition (go-asn1#235).
const (
	rlfV1250Complete   = "5c155060990021040040202468ac00090c80"
	rlfV1250Incomplete = "5c155060990021040040202468ac00050c"
	rlfV1250Offset     = 118
	rlfV1250Path       = "ULDCCHMessage.Message.C1.UeInformationResponseR9.CriticalExtensions.C1.UeInformationResponseR9.RlfReportR9.ExtData_[3]"
)

func TestLTERRCIncompleteExtensionOffset(t *testing.T) {
	incomplete := mustHex(t, rlfV1250Incomplete)
	var recovered uper.ToleranceLog
	var message rrc.ULDCCHMessage
	if err := message.UnmarshalUPERWithOptions(incomplete, uper.DecodeOptions{ExtensionRecoveryTolerance: &recovered}); err != nil {
		t.Fatalf("incomplete addition: %v", err)
	}
	records := recovered.Snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%+v", records)
	}
	if r := records[0]; r.Kind != uper.ToleratedIncompleteExtension || r.Path != rlfV1250Path || r.Offset != rlfV1250Offset ||
		r.DeclaredLength != 1 || r.ConsumedBits != 8 || r.Bits.BitLength != 8 || !errors.Is(r.Err, uper.ErrTruncated) {
		t.Fatalf("incomplete record=%+v, want Offset %d", r, rlfV1250Offset)
	}
	if replay, err := message.MarshalUPER(); err != nil || !bytes.Equal(replay, incomplete) {
		t.Fatalf("replay=%x %v, want %x", replay, err, incomplete)
	}

	complete := mustHex(t, rlfV1250Complete)
	var cuts uper.ToleranceLog
	var cut rrc.ULDCCHMessage
	if err := cut.UnmarshalUPERWithOptions(complete[:len(complete)-2], uper.DecodeOptions{TruncatedExtensionTolerance: &cuts}); err != nil {
		t.Fatalf("cut addition: %v", err)
	}
	if c := cuts.Snapshot(); len(c) != 1 || c[0].Kind != uper.ToleratedTruncatedExtension || c[0].Path != rlfV1250Path || c[0].Offset != rlfV1250Offset {
		t.Fatalf("cut records=%+v, want Offset %d", c, rlfV1250Offset)
	}
}
