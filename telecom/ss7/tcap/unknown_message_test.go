package tcap_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func unknownMessageTLV(identifier byte, contents []byte) []byte {
	return append(append([]byte{identifier}, ber.EncodeLength(len(contents))...), contents...)
}

func TestUnknownMessageDiagnostics(t *testing.T) {
	for _, encoded := range []string{"048103616263", "24050403616263", "3006048103616263"} {
		argument, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, component := range []byte{0xa1, 0xa2, 0xa7, 0xa3} {
			fields := append([]byte{2, 1, 0, 2, 1, 0}, argument...)
			if component == 0xa2 || component == 0xa7 {
				fields = append([]byte{2, 1, 0}, unknownMessageTLV(0x30, append([]byte{2, 1, 0}, argument...))...)
			}
			portion := unknownMessageTLV(0x6c, unknownMessageTLV(component, fields))
			for _, outer := range []byte{0x60, 0x63, 0x66, 0x68} {
				data := unknownMessageTLV(outer, append([]byte{0x48, 1, 1}, portion...))
				for _, tolerant := range []bool{false, true} {
					t.Run(fmt.Sprintf("tag-%x/component-%x/value-%s/tolerant-%t", outer, component, encoded, tolerant), func(t *testing.T) {
						var value wire.TCMessage
						var log ber.ViolationLog
						var opts []ber.DecodeOption
						if tolerant {
							opts = append(opts, ber.WithTolerance(&log))
						}
						if err := ber.ValidateBERElement(data, ber.TrackTCAPForm(opts, "TCMessage")...); err != nil {
							t.Fatal(err)
						}
						err := value.UnmarshalBER(data, opts...)
						want := fmt.Sprintf("decoding TCMessage: ber: unexpected or missing element: unknown tag [APPLICATION %d CONSTRUCTED] for TCMessage CHOICE", outer&31)
						if err == nil || err.Error() != want {
							t.Fatalf("error=%v, want %s", err, want)
						}
						for _, sentinel := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
							if errors.Is(err, sentinel) != (sentinel == ber.ErrUnexpectedElement) {
								t.Fatalf("error=%v sentinel=%v", err, sentinel)
							}
						}
						var located *wire.DecodeError
						if !errors.As(err, &located) || located.Path != "TCMessage" {
							t.Fatalf("location=%+v", located)
						}
						prefix, err := json.Marshal(located.Prefix)
						if err != nil {
							t.Fatal(err)
						}
						if fmt.Sprintf("%x", sha256.Sum256(prefix)) != "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d" {
							t.Fatalf("prefix=%s", prefix)
						}
						if len(log.Snapshot()) != 0 {
							t.Fatalf("unadmitted message acquired profile reports: %+v", log.Snapshot())
						}
					})
				}
			}
		}
	}
}
