// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external_open_contents_test.go; SHA-256 7615b08d479629f1381770c3dd619de530157f166f4df0c00571a29ed6157724.
package ber

import (
	"encoding/hex"
	"testing"
)

// X.690 (02/2021) §§8.6.2.2, 8.14.4, 8.18.1: an EXTERNAL's
// arbitrary choice retains the BIT STRING count rule inside open values.
// The containing profile stops at those values (§8.15).
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
				want = ErrInvalidValue
			}
			assertElementSentinels(t, ValidateBERElement(data, TrackTCAPForm(nil)...), want)
			options := TrackTCAPForm(nil)
			owned, err := OwnGeneratedBERInput(data, options)
			if err == nil {
				_, _, err = PrepareGeneratedBERInput(owned, options)
			}
			assertElementSentinels(t, err, want)
		})
	}
}
