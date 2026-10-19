package validation

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// Synthetic SendRoutingInfoArg values (TS 29.002 §17.7.3). The addresses use
// country code 999, which ITU-T E.164 reserves, so no value is a subscriber's.
const (
	sriArg            = "30158007919909000000f18301008607919909000000f2"
	sriArgInterrogate = "30178007919909000000f183010084008607919909000000f2"
)

func TestSendRoutingInfoArgSynthetic(t *testing.T) {
	for _, tc := range []struct {
		wire     string
		orInterr bool
	}{{sriArg, false}, {sriArgInterrogate, true}} {
		wire := mustHex(t, tc.wire)
		var arg gsm_map.SendRoutingInfoArg
		if err := arg.UnmarshalBER(wire); err != nil {
			t.Fatalf("%s: strict decode: %v", tc.wire, err)
		}
		if !bytes.Equal(arg.Msisdn, mustHex(t, "919909000000f1")) || !bytes.Equal(arg.GmscOrGsmSCFAddress, mustHex(t, "919909000000f2")) {
			t.Fatalf("%s: addresses %x, %x", tc.wire, arg.Msisdn, arg.GmscOrGsmSCFAddress)
		}
		if arg.InterrogationType != gsm_map.InterrogationTypeBasicCall || (arg.OrInterrogation != nil) != tc.orInterr {
			t.Fatalf("%s: interrogation %v, or-Interrogation %v", tc.wire, arg.InterrogationType, arg.OrInterrogation != nil)
		}
		for name, encode := range map[string]func() ([]byte, error){
			"replay":           func() ([]byte, error) { return arg.MarshalBER() },
			"WithoutBERReplay": func() ([]byte, error) { return arg.MarshalBER(mapber.WithoutBERReplay()) },
			"DER":              arg.MarshalDER,
		} {
			if out, err := encode(); err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("%s: %s = %x, %v", tc.wire, name, out, err)
			}
		}
	}
}

// Any SendRoutingInfoArg that strict decoding accepts replays byte for byte.
func FuzzSendRoutingInfoArg(f *testing.F) {
	for _, seed := range []string{sriArg, sriArgInterrogate} {
		f.Add(mustHexF(f, seed))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		var arg gsm_map.SendRoutingInfoArg
		if arg.UnmarshalBER(wire) != nil {
			return
		}
		if out, err := arg.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%x: replay = %x, %v", wire, out, err)
		}
	})
}
