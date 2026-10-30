package tcap_test

import (
	"bytes"
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"testing"
)

// X.690 (02/2021) §§8.6.2.2, 8.14.4, 8.18.1 apply to EXTERNAL
// inside a TC-user value, independently of the profile boundary (§8.15).
func TestExternalContentsInsideOpenValues(t *testing.T) {
	for _, row := range []struct {
		name, wire string
		invalid    bool
	}{
		{"argument/invalid", "62174801016c12a11002010102012d280806032a0304820108", true},
		{"argument/long-length", "62134801016c0ea10c02010102012d048103616263", false},
		{"argument/constructed-octets", "62144801016c0fa10d02010102012d24050403616263", false},
		{"result/invalid", "64194901016c14a212020101300d02012d280806032a0304820108", true},
		{"result/long-length", "64154901016c10a20e020101300902012d048103616263", false},
		{"result/constructed-octets", "64164901016c11a20f020101300a02012d24050403616263", false},
		{"parameter/invalid", "64174901016c12a310020101020101280806032a0304820108", true},
		{"parameter/long-length", "64134901016c0ea30c020101020101048103616263", false},
		{"parameter/constructed-octets", "64144901016c0fa30d02010102010124050403616263", false},
		{"user-information/invalid", "62384801016b332831060700118605010101a026602480020780a109060704000001000503be13281106032a0304a00a280806032a0304820108", true},
		{"user-information/long-length", "62344801016b2f282d060700118605010101a022602080020780a109060704000001000503be0f280d06032a0304a006048103616263", false},
		{"user-information/constructed-octets", "62354801016b30282e060700118605010101a023602180020780a109060704000001000503be10280e06032a0304a00724050403616263", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			var want error
			if row.invalid {
				want = ber.ErrInvalidValue
			}
			assertImplicitSentinels(t, ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...), want)
			for _, tolerant := range []bool{false, true} {
				var value tcap.TCMessage
				var options []ber.DecodeOption
				if tolerant {
					options = append(options, ber.WithTolerance(new(ber.ViolationLog)))
				}
				err = value.UnmarshalBER(data, options...)
				assertImplicitSentinels(t, err, want)
				if err == nil {
					replay, encodeErr := value.MarshalBER()
					if encodeErr != nil || !bytes.Equal(replay, data) {
						t.Fatalf("tolerant=%v replay=%x error=%v", tolerant, replay, encodeErr)
					}
				}
			}
		})
	}
}
