package gsm_map_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	values "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"testing"
)

// X.690 (02/2021) §§8.23.1, 8.23.4–8.23.8: foreign open values
// retain contents validation and representable violations retain replay.
func TestRestrictedStringPrivateExtension(t *testing.T) {
	for _, tail := range []string{"1e0100", "1c03000000", "120141", "130121", "1601ff", "1a01ff"} {
		t.Run(tail, func(t *testing.T) {
			inner, err := hex.DecodeString(tail)
			if err != nil {
				t.Fatal(err)
			}
			content := append([]byte{6, 2, 42, 3}, inner...)
			wire := append([]byte{48, byte(len(content))}, content...)
			var value values.PrivateExtension
			err = value.UnmarshalBER(wire)
			if !errors.Is(err, ber.ErrInvalidValue) || errors.Is(err, ber.ErrUnexpectedElement) {
				t.Fatalf("strict: %v", err)
			}
			var located interface{ ASN1BERPath() string }
			if !errors.As(err, &located) || located.ASN1BERPath() != "extType" {
				t.Fatalf("strict Path: %v", err)
			}
			var log ber.ViolationLog
			err = value.UnmarshalBER(wire, ber.WithTolerance(&log))
			undecodable := inner[0] == 30 || inner[0] == 28
			if undecodable {
				if !errors.Is(err, ber.ErrInvalidValue) || len(log.Snapshot()) != 0 {
					t.Fatalf("tolerant invalid width: %v records=%d", err, len(log.Snapshot()))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			records := log.Snapshot()
			if len(records) != 1 || records[0].Path != "extType" {
				t.Fatalf("reports=%+v", records)
			}
			log.Reset()
			replay, err := value.MarshalBER(ber.WithTolerance(&log))
			if err != nil || !bytes.Equal(replay, wire) || len(log.Snapshot()) != 1 {
				t.Fatalf("replay err=%v equal=%v reports=%+v", err, bytes.Equal(replay, wire), log.Snapshot())
			}
			if _, err := value.MarshalDER(); !errors.Is(err, ber.ErrInvalidValue) {
				t.Fatalf("DER: %v", err)
			}
		})
	}
}
