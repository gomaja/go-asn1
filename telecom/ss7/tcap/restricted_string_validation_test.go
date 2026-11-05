package tcap_test

import (
	"encoding/hex"
	"errors"
	tcap "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"testing"
)

// X.690 (02/2021) §8.23.8: a TC-user's open value retains its
// universal contents rules independently of the surrounding TCAP syntax.
func TestRestrictedStringTCUserArgument(t *testing.T) {
	wire, err := hex.DecodeString("62104801016c0ba1090201010201011e0100")
	if err != nil {
		t.Fatal(err)
	}
	for _, tolerant := range []bool{false, true} {
		var log ber.ViolationLog
		var options []ber.DecodeOption
		if tolerant {
			options = append(options, ber.WithTolerance(&log))
		}
		var message tcap.TCMessage
		err := message.UnmarshalBER(wire, options...)
		if !errors.Is(err, ber.ErrInvalidValue) || errors.Is(err, ber.ErrUnexpectedElement) {
			t.Fatalf("tolerant=%v: %v", tolerant, err)
		}
		var located interface{ ASN1BERPath() string }
		if !errors.As(err, &located) || located.ASN1BERPath() != "child[1].child[0].child[2]" {
			t.Fatalf("missing argument Path: %v", err)
		}
		t.Logf("tolerant=%v Path=%s reports=%d", tolerant, located.ASN1BERPath(), len(log.Snapshot()))
		if len(log.Snapshot()) != 0 {
			t.Fatal("undecodable value published tolerance records")
		}
	}
}
