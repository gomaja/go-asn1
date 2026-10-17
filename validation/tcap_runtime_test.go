package validation

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// Q.773 (06/1997), DialoguePDUs AARQ-apdu; X.690 (02/2021) §8.14.3:
// an EXPLICIT wrapper contains exactly one complete base encoding.
func TestExplicitWrapperRejectsTrailingAARQ(t *testing.T) {
	valid := mustHex(t, "600ba109060704000001000103")
	var request tcap.AARQApdu
	if err := request.UnmarshalBER(valid); err != nil {
		t.Fatal(err)
	}
	for kind, encode := range map[string]func() ([]byte, error){
		"BER": func() ([]byte, error) { return request.MarshalBER() }, "DER": request.MarshalDER,
	} {
		if wire, err := encode(); err != nil || !bytes.Equal(wire, valid) {
			t.Fatalf("%s = %x, %v", kind, wire, err)
		}
	}
	want := runtime.MustObjectIdentifierFromArcs(0, 4, 0, 0, 1, 0, 1, 3)
	if !request.ApplicationContextName.Equal(want) {
		t.Fatalf("application-context-name = %v, want %v", request.ApplicationContextName, want)
	}
	invalid := mustHex(t, "600da10b0607040000010001030500")
	for _, tolerant := range []bool{false, true} {
		var value tcap.AARQApdu
		var log ber.ViolationLog
		var options []ber.DecodeOption
		if tolerant {
			options = append(options, ber.WithConstraintTolerance(&log))
		}
		if err := value.UnmarshalBER(invalid, options...); !errors.Is(err, ber.ErrExtraData) {
			t.Fatalf("tolerant=%v: %v", tolerant, err)
		}
		if len(log.Snapshot()) != 0 {
			t.Fatal("invalid structure reported a constraint violation")
		}
	}
}

func FuzzTCAPReleaseConstraints(f *testing.F) {
	for _, text := range []string{
		"160180", "1a02411f", "61051203323041", "610413024640",
		"300b800100aa0680020640a100", "3006810100810100",
		"30820144a0820140" + strings.Repeat("3003800101", 64),
		"305a800100a255" + strings.Repeat("3003800101", 17),
	} {
		f.Add(mustHexF(f, text))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		var strict tcap.AARQApdu
		strictErr := strict.UnmarshalBER(wire)
		if strictErr == nil {
			if replay, err := strict.MarshalBER(); err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("strict replay = %x, %v", replay, err)
			}
		}
		var log ber.ViolationLog
		option := ber.WithConstraintTolerance(&log)
		var tolerant tcap.AARQApdu
		if err := tolerant.UnmarshalBER(wire, option); err != nil {
			if strictErr == nil {
				t.Fatalf("tolerant rejected strict value: %v", err)
			}
			return
		}
		if strictErr == nil && len(log.Snapshot()) != 0 {
			t.Fatalf("strict value reported %+v", log.Snapshot())
		}
		if replay, err := tolerant.MarshalBER(option); err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("tolerant replay = %x, %v", replay, err)
		}
	})
}
