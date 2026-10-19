package validation

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #184: Q.773 (06/1997) §4.1.1 applies "to TC messages as well as to
// the other abstract syntaxes defined in this Recommendation". An Invoke
// argument, a ReturnResult result and a ReturnError parameter carry a
// TC-user value, an open type (X.690 (02/2021) §8.15), so their encoding is
// the TC-user codec's to check. TCAP's own elements still follow §4.1.1.
func TestTCAPProfileLeavesTCUserContent(t *testing.T) {
	for _, c := range []struct{ name, hex string }{
		{"Invoke argument with outer length 8103", "62164804000000016c0ea10c020101020102308103040100"},
		{"Invoke argument with inner length 8101", "62164804000000016c0ea10c020101020102300404810100"},
		{"Invoke argument holding a constructed OCTET STRING", "62184804000000016c10a10e0201010201023006240404020000"},
		{"ReturnResultLast result with outer length 8103", "64184904000000016c10a20e0201013009020102308103040100"},
		{"ReturnError parameter with outer length 8103", "64164904000000016c0ea30c020101020105308103040100"},
	} {
		wire := mustHex(t, c.hex)
		var message tcap.TCMessage
		if err := message.UnmarshalBER(wire); err != nil {
			t.Errorf("%s: strict decode = %v; want accepted", c.name, err)
			continue
		}
		if got, err := message.MarshalBER(); err != nil || !bytes.Equal(got, wire) {
			t.Errorf("%s: strict replay = %x, %v; want %x", c.name, got, err, wire)
		}
	}
	var own tcap.TCMessage
	if err := own.UnmarshalBER(mustHex(t, "6216488104000000016c0da10b0201010201023003040100")); !errors.Is(err, tcapber.ErrInvalidValue) {
		t.Fatalf("TCAP's own otid with a long-form length: strict decode = %v; want refused", err)
	}
}
