package validation

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #185: a Q.773 dialogue APDU is TCAP's own syntax (Q.773 (06/1997)
// §§3.2, 4.1.1, 4.2.3). X.690 (02/2021) §§8.6.4, 8.7.3 and 8.18.10–8.18.11 let
// EXTERNAL carry it in segments. Tolerant decoding reports a violation inside
// the reassembled APDU once, at the wire offset of the violating element, as
// it does for the unsegmented form, and External() returns the tolerated APDU
// either way. Each row's AARQ carries protocol-version as a constructed BIT
// STRING.
func TestTCAPSegmentedDialogueReportsCarriedAPDU(t *testing.T) {
	const path = "begin.dialoguePortion.dialogue.dialogueRequest.protocol-version"
	element := []byte{0xa0, 0x04, 0x03, 0x02, 0x07, 0x80}
	for _, c := range []struct{ name, hex string }{
		{"octet-aligned, primitive", "62274801016b22282006070011860501010181156013a00403020780a10b06092b0601040183b20302"},
		{"octet-aligned, two segments", "622b4801016b262824060700118605010101a119040160041413a00403020780a10b06092b0601040183b20302"},
		{"octet-aligned, nested segments", "622d4801016b282826060700118605010101a11b0401602416041413a00403020780a10b06092b0601040183b20302"},
		{"arbitrary, two segments", "622d4801016b282826060700118605010101a21b0302006003150013a00403020780a10b06092b0601040183b20302"},
		{"arbitrary, nested segments", "622f4801016b2a2828060700118605010101a21d03020060231703150013a00403020780a10b06092b0601040183b20302"},
	} {
		wire := mustHex(t, c.hex)
		var message tcap.TCMessage
		var log tcapber.ViolationLog
		if err := message.UnmarshalBER(wire, tcapber.WithTolerance(&log)); err != nil {
			t.Errorf("%s: tolerant decode = %v", c.name, err)
			continue
		}
		var reports []tcapber.Violation
		for _, v := range log.Snapshot() {
			if v.Path == path && v.Constraint == "Q.773 §4.1.1: primitive-bit-string" {
				reports = append(reports, v)
			}
		}
		if len(reports) != 1 || reports[0].Offset == nil || *reports[0].Offset != bytes.Index(wire, element) {
			t.Errorf("%s: protocol-version reports = %+v; want one at offset %d", c.name, reports, bytes.Index(wire, element))
		}
		if _, err := message.Begin.DialoguePortion.External(); err != nil {
			t.Errorf("%s: External() = %v; want the tolerated APDU", c.name, err)
		}
		if replay, err := message.MarshalBER(tcapber.WithTolerance(&tcapber.ViolationLog{})); err != nil || !bytes.Equal(replay, wire) {
			t.Errorf("%s: tolerant replay = %x, %v; want %x", c.name, replay, err, wire)
		}
	}
}
