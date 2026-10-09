package validation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/rrc"
)

// UL-DCCH-Message ueInformationResponse-r9 carrying an RLF-Report-r9 with
// measResultLastServCell-r9 {rsrpResult-r9 25, rsrqResult-r9 21} and the
// extension addition group of measResultLastServCell-v1250 and
// lastServCellRSRQ-Type-r12. The group is the last open type of the PDU
// (ITU-T X.691 (02/2021) §19.9): its length determinant, 00000010, starts at
// bit 46 and declares 2 octets of contents, bits 54 to 69; bits 70 and 71
// are the final padding. Cutting the last octet leaves 10 of the 16 content
// bits; cutting two leaves 2. pycrate 0.7.11 decodes the complete PDU to
// this value and rejects both cut forms ("length determinant too long").
const (
	rlfReportComplete = "5a1532a89100099000"
	rlfReportCutOne   = "5a1532a891000990"
	rlfReportCutTwo   = "5a1532a8910009"
	rlfGroupOffset    = 46
	rlfGroupBits      = 8 + 16
)

func rlfReport(t *testing.T, message *rrc.ULDCCHMessage) *rrc.RLFReportR9 {
	t.Helper()
	c1 := message.Message.C1
	if c1 == nil || c1.UeInformationResponseR9 == nil {
		t.Fatal("not a ueInformationResponse-r9")
	}
	ies := c1.UeInformationResponseR9.CriticalExtensions.C1
	if ies == nil || ies.UeInformationResponseR9 == nil || ies.UeInformationResponseR9.RlfReportR9 == nil {
		t.Fatal("no rlf-Report-r9")
	}
	return ies.UeInformationResponseR9.RlfReportR9
}

// bitsFrom returns the bits of wire from offset to its end, MSB first.
func bitsFrom(wire []byte, offset int) per.TrailingBits {
	length := len(wire)*8 - offset
	out := make([]byte, (length+7)/8)
	for i := range length {
		bit := offset + i
		if wire[bit/8]&(0x80>>(bit%8)) != 0 {
			out[i/8] |= 0x80 >> (i % 8)
		}
	}
	return per.TrailingBits{Bytes: out, BitLength: length}
}

func TestTruncatedExtensionAddition(t *testing.T) {
	complete := mustHex(t, rlfReportComplete)
	var whole rrc.ULDCCHMessage
	var none per.ToleranceLog
	if err := whole.UnmarshalUPERWithOptions(complete, per.DecodeOptions{TruncatedExtensionTolerance: &none}); err != nil {
		t.Fatalf("complete PDU: %v", err)
	}
	if records := none.Snapshot(); len(records) != 0 {
		t.Fatalf("complete PDU logged %+v", records)
	}
	if report := rlfReport(t, &whole); report.MeasResultLastServCellV1250 == nil || report.LastServCellRSRQTypeR12 == nil {
		t.Fatal("complete PDU lost the v1250 group")
	}
	if out, err := whole.MarshalUPER(); err != nil || !bytes.Equal(out, complete) {
		t.Fatalf("complete PDU re-encodes %x, %v; want %x", out, err, complete)
	}

	for _, vector := range []string{rlfReportCutOne, rlfReportCutTwo} {
		t.Run(vector, func(t *testing.T) {
			wire := mustHex(t, vector)
			var strict rrc.ULDCCHMessage
			if err := strict.UnmarshalUPER(wire); err == nil {
				t.Fatal("strict decode accepted a cut extension addition")
			}

			var cuts per.ToleranceLog
			var message rrc.ULDCCHMessage
			if err := message.UnmarshalUPERWithOptions(wire, per.DecodeOptions{TruncatedExtensionTolerance: &cuts}); err != nil {
				t.Fatalf("tolerant decode: %v", err)
			}
			records := cuts.Snapshot()
			if len(records) != 1 {
				t.Fatalf("logged %+v, want one record", records)
			}
			cut := records[0]
			arrived := bitsFrom(wire, rlfGroupOffset)
			if cut.Kind != per.ToleratedTruncatedExtension || !strings.HasSuffix(cut.Path, ".RlfReportR9.ExtData_[3]") ||
				cut.Offset != rlfGroupOffset || cut.Missing != rlfGroupBits-arrived.BitLength ||
				cut.Bits.BitLength != arrived.BitLength || !bytes.Equal(cut.Bits.Bytes, arrived.Bytes) {
				t.Fatalf("logged %+v; want the group at bit %d with %d bits missing", cut, rlfGroupOffset, rlfGroupBits-arrived.BitLength)
			}

			report := rlfReport(t, &message)
			if report.MeasResultLastServCellR9.RsrpResultR9 != 25 || report.MeasResultLastServCellR9.RsrqResultR9 == nil ||
				*report.MeasResultLastServCellR9.RsrqResultR9 != 21 {
				t.Fatalf("root = %+v", report.MeasResultLastServCellR9)
			}
			if report.MeasResultLastServCellV1250 != nil || report.LastServCellRSRQTypeR12 != nil {
				t.Fatal("the cut group has a value")
			}
			if out, err := message.MarshalUPER(); err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("unchanged value re-encodes %x, %v; want %x", out, err, wire)
			}

			// An edit before the cut encodes the value anew, without the cut
			// group, and a strict decode accepts the result.
			report.MeasResultLastServCellR9.RsrpResultR9 = 26
			edited, err := message.MarshalUPER()
			if err != nil {
				t.Fatal(err)
			}
			var again rrc.ULDCCHMessage
			if err := again.UnmarshalUPER(edited); err != nil {
				t.Fatalf("strict decode of the edit %x: %v", edited, err)
			}
			if got := rlfReport(t, &again); got.MeasResultLastServCellR9.RsrpResultR9 != 26 ||
				got.MeasResultLastServCellV1250 != nil || got.LastServCellRSRQTypeR12 != nil {
				t.Fatalf("edit decodes to %+v", got)
			}
		})
	}
}
