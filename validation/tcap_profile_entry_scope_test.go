package validation

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	tcapber "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// go-asn1 #191: a source-less TrackTCAPForm scan applies Q.773 (06/1997)
// §4.1.1 with the same scope as TCMessage.UnmarshalBER. It checks TCAP's own
// syntax, including the dialogue APDU and IMPLICIT strings, and leaves the
// TC-user's argument, result and parameter values alone (X.690 (02/2021)
// §8.15). The source generated decoders pass gives the same result.
func TestTCAPProfileEntryScopeMatchesDecoder(t *testing.T) {
	for _, c := range []struct{ name, hex string }{
		// Invoke argument [APPLICATION 11] {} with its zero length in long form.
		{"TC-user argument", "62104801016c0ba1090201010201016b8100"},
		// Abort whose dialogue APDU holds a constructed BIT STRING.
		{"dialogue APDU", "67174901026b122810060700118605010101a0052303800100"},
		// Begin whose OTID [APPLICATION 8] is a constructed OCTET STRING.
		{"constructed OTID", "6206680404020102"},
	} {
		wire := mustHex(t, c.hex)
		var message tcap.TCMessage
		decoded := message.UnmarshalBER(wire)
		for _, scan := range []struct {
			name string
			err  error
		}{
			{"no source", tcapber.ValidateBERElement(wire, tcapber.TrackTCAPForm(nil)...)},
			{"empty source", tcapber.ValidateBERElement(wire, tcapber.TrackTCAPForm(nil, "")...)},
			{"decoder source", tcapber.ValidateBERElement(wire, tcapber.TrackTCAPForm(nil, "TCMessage", "TCAPMessages", "TCMessage")...)},
		} {
			if (decoded == nil) != (scan.err == nil) {
				t.Errorf("%s, %s: scan = %v, decoder = %v; want the same verdict", c.name, scan.name, scan.err, decoded)
				continue
			}
			if decoded == nil {
				continue
			}
			var fromDecoder, fromScan *tcapber.ValidationError
			var atDecoder, atScan *tcapber.ElementError
			if !errors.As(decoded, &fromDecoder) || !errors.As(scan.err, &fromScan) || fromScan.Constraint != fromDecoder.Constraint {
				t.Errorf("%s, %s: scan = %v, decoder = %v; want the same §4.1.1 rule", c.name, scan.name, scan.err, decoded)
				continue
			}
			if !errors.As(decoded, &atDecoder) || !errors.As(scan.err, &atScan) || atScan.Offset() != atDecoder.Offset() || !reflect.DeepEqual(atScan.ChildIndexes(), atDecoder.ChildIndexes()) {
				t.Errorf("%s, %s: scan located at %v, decoder at %v; want the same element", c.name, scan.name, scan.err, decoded)
			}
		}
	}
}
