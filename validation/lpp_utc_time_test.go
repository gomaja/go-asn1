package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/lpp"
)

// lppUTCTimeWire is the UPER encoding of UTC-Time-r15 {utcTime-r15
// "260927114530Z", utcTime-ms-r15 123} produced by pycrate 0.7.11. The type
// is the TS 37.355 V19.3.0 alternative of DisplacementTimeStamp-r15.
const lppUTCTimeWire = "06b26cc1cb26ec58b46acd85a1ec"

func TestLPPUTCTimeVector(t *testing.T) {
	wire, err := hex.DecodeString(lppUTCTimeWire)
	if err != nil {
		t.Fatal(err)
	}
	var decoded lpp.UTCTimeR15
	if err := decoded.UnmarshalUPER(wire); err != nil {
		t.Fatal(err)
	}
	if decoded.UtcTimeR15.String() != "260927114530Z" || decoded.UtcTimeMsR15 != 123 {
		t.Fatalf("decoded %s / %d", decoded.UtcTimeR15, decoded.UtcTimeMsR15)
	}
	encoded, err := decoded.MarshalUPER()
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("re-encode = %x, %v; want %s", encoded, err, lppUTCTimeWire)
	}

	// X.691 (02/2021) §10.6.5 encodes the X.690 §11.8 canonical form, so
	// the same instant written with a differential gives the same wire.
	for _, text := range []string{"260927124530+0100", "260927064530-0500"} {
		value, err := runtime.ParseUTCTime(text)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		fresh := lpp.UTCTimeR15{UtcTimeR15: value, UtcTimeMsR15: 123}
		got, err := fresh.MarshalUPER()
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("%s encodes %x, %v; want %s", text, got, err, lppUTCTimeWire)
		}
	}

	// 491231230000-0100 is 2050-01-01T00:00:00Z, outside the UTCTime window
	// of RFC 5280 §4.1.2.5.1, so it has no canonical PER form.
	late, err := runtime.ParseUTCTime("491231230000-0100")
	if err != nil {
		t.Fatal(err)
	}
	outside := lpp.UTCTimeR15{UtcTimeR15: late, UtcTimeMsR15: 1}
	if _, err := outside.MarshalUPER(); !errors.Is(err, runtime.ErrNoCanonicalTime) || !errors.Is(err, per.ErrInvalidValue) {
		t.Fatalf("out-of-window error = %v", err)
	}
}
