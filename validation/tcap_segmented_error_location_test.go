package validation

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #189: a structural failure inside a dialogue APDU carried in
// segmented EXTERNAL encoding is located at the offending element's first
// wire octet, with child indexes that are logical within the reassembled
// APDU, as in primitive carriage (X.690 (02/2021) §§8.6.4, 8.7.3,
// 8.18.10–8.18.11; Q.773 (06/1997) §§3.2, 4.2.3).
func TestTCAPSegmentedDialogueStructuralErrorLocation(t *testing.T) {
	for _, c := range []struct {
		name     string
		hex      string
		offset   int
		children []int
	}{
		// protocol-version declares 127 octets where 4 follow.
		{"primitive octet-aligned", "62274801016b22282006070011860501010181156013a07f03020780a10b06092b0601040183b20302", 22, []int{1, 0, 1, 0, 0}},
		{"two octet-aligned segments", "622b4801016b262824060700118605010101a119040160041413a07f03020780a10b06092b0601040183b20302", 26, []int{1, 0, 1, 0, 0}},
		// The reassembled APDU is a truncated high-tag-number identifier.
		{"truncated root identifier in a segment", "62154801016b10280e060700118605010101a10304017f", 22, []int{1, 0, 1, 0}},
	} {
		var message tcap.TCMessage
		err := message.UnmarshalBER(mustHex(t, c.hex), tcapber.WithTolerance(&tcapber.ViolationLog{}))
		var located *tcapber.ElementError
		if !errors.As(err, &located) {
			t.Errorf("%s: tolerant decode = %v; want a located refusal", c.name, err)
			continue
		}
		if located.Offset() != c.offset || !reflect.DeepEqual(located.ChildIndexes(), c.children) {
			t.Errorf("%s: refusal at offset %d %v; want %d %v", c.name, located.Offset(), located.ChildIndexes(), c.offset, c.children)
		}
	}
}
