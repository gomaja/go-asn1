package tcap_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// Q.773 (06/1997) §4.1.1; X.690 (02/2021) §8.15.
func TestMisplacedComponentDiagnostics(t *testing.T) {
	for _, row := range []struct{ name, root, hex, failure, path, prefix string }{
		{"issue-0", "TCMessage", "621548010105006c0ea10c020100020100048103616263", "decoding begin: ber: decode Begin at offset 3: ber: unexpected or missing element", "begin", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"issue-0-sequence", "Begin", "301548010105006c0ea10c020100020100048103616263", "ber: decode Begin at offset 3: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-1", "TCMessage", "621648010105006c0fa10d02010002010024050403616263", "decoding begin: ber: decode Begin at offset 3: ber: unexpected or missing element", "begin", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"issue-1-sequence", "Begin", "301648010105006c0fa10d02010002010024050403616263", "ber: decode Begin at offset 3: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-2", "TCMessage", "621748010105006c10a20e0201003009020100048103616263", "decoding begin: ber: decode Begin at offset 3: ber: unexpected or missing element", "begin", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"issue-2-sequence", "Begin", "301748010105006c10a20e0201003009020100048103616263", "ber: decode Begin at offset 3: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-3", "TCMessage", "621548010105006c0ea30c020100020100048103616263", "decoding begin: ber: decode Begin at offset 3: ber: unexpected or missing element", "begin", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"issue-3-sequence", "Begin", "301548010105006c0ea30c020100020100048103616263", "ber: decode Begin at offset 3: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-4", "TCMessage", "65134801016c0ea10c020100020100048103616263", "decoding continue: ber: unexpected or missing element: expected tag [APPLICATION 9] for dtid, got [APPLICATION 12 CONSTRUCTED]", "continue", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"issue-4-sequence", "Continue", "30134801016c0ea10c020100020100048103616263", "ber: unexpected or missing element: expected tag [APPLICATION 9] for dtid, got [APPLICATION 12 CONSTRUCTED]", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-5", "TCMessage", "67134901016c0ea10c020100020100048103616263", "decoding abort: ber: decode Abort at offset 3: ber: unexpected or missing element", "abort", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"issue-5-sequence", "Abort", "30134901016c0ea10c020100020100048103616263", "ber: decode Abort at offset 3: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-6", "TCMessage", "62134801016c0ea10c020100020100048103616263", "<nil>", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-6-sequence", "Begin", "30134801016c0ea10c020100020100048103616263", "<nil>", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"issue-7", "TCMessage", "651748010149010205006b0d280b06012aa006048103616263", "decoding continue: ber: decode Continue at offset 6: ber: unexpected or missing element", "continue", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"issue-7-sequence", "Continue", "301748010149010205006b0d280b06012aa006048103616263", "ber: decode Continue at offset 6: ber: unexpected or missing element", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
	} {
		t.Run(row.name+"/"+row.root, func(t *testing.T) {
			data, err := hex.DecodeString(row.hex)
			if err != nil {
				t.Fatal(err)
			}
			var want error
			if row.failure != "<nil>" {
				want = ber.ErrUnexpectedElement
			}
			for _, tolerant := range []bool{false, true} {
				var log ber.ViolationLog
				var opts []ber.DecodeOption
				if tolerant {
					opts = append(opts, ber.WithTolerance(&log))
				}
				scanOptions := ber.TrackTCAPForm(opts, row.root)
				if err := ber.ValidateBERElement(data, scanOptions...); err != nil {
					t.Fatalf("scan: %v", err)
				}
				var value interface {
					UnmarshalBER([]byte, ...ber.DecodeOption) error
					MarshalBER(...ber.EncodeOption) ([]byte, error)
				}
				switch row.root {
				case "TCMessage":
					value = new(wire.TCMessage)
				case "Begin":
					value = new(wire.Begin)
				case "Continue":
					value = new(wire.Continue)
				case "Abort":
					value = new(wire.Abort)
				}
				err = value.UnmarshalBER(data, opts...)
				if fmt.Sprint(err) != row.failure {
					t.Fatalf("tolerant=%t: %v, want %s", tolerant, err, row.failure)
				}
				for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
					if errors.Is(err, sentinel) != (sentinel == want) {
						t.Fatalf("%v: errors.Is(%v), want %v", err, sentinel, want)
					}
				}
				path := ""
				var prefix any
				var located *wire.DecodeError
				if errors.As(err, &located) {
					path, prefix = located.Path, located.Prefix
				}
				raw, jsonErr := json.Marshal(prefix)
				if jsonErr != nil {
					t.Fatal(jsonErr)
				}
				if path != row.path || fmt.Sprintf("%x", sha256.Sum256(raw)) != row.prefix {
					t.Fatalf("path/prefix changed: %s %s", path, raw)
				}
				if len(log.Snapshot()) != 0 {
					t.Fatalf("unexpected tolerance record: %+v", log.Snapshot())
				}
				if err == nil {
					replay, encodeErr := value.MarshalBER()
					if encodeErr != nil || !bytes.Equal(data, replay) {
						t.Fatalf("replay=%x: %v", replay, encodeErr)
					}
				}
			}
		})
	}
}
