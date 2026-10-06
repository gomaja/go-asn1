package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	umts "github.com/gomaja/go-asn1/telecom/umts/rrc"
)

// RRCConnectionSetupComplete-v8a0-IEs with lateNonCriticalExtension, an
// OCTET STRING (CONTAINING RRCConnectionSetupComplete-v8x0-IEs). pycrate
// 0.7.11 encodes the empty contained value as 804000. In 806000 the
// contained octet 0x80 announces a lateNonCriticalExtension of its own
// without its length, so only the contained value fails (pycrate: "bitlen
// overflow"); the enclosing OCTET STRING is intact.
const (
	lateValid   = "804000"
	lateCorrupt = "806000"
)

func deferring(mode per.ContainedDecoding) (per.DecodeOptions, *per.DeferralLog) {
	var log per.DeferralLog
	return per.DecodeOptions{ContainedDecoding: mode, Deferrals: &log}, &log
}

// TS 36.331 V19.4.0 8.1: an error in a contained value should not fail the
// whole decode. DeferOnError keeps the value raw, with its error.
func TestDeferOnErrorKeepsCorruptLateNonCriticalExtension(t *testing.T) {
	wire, _ := hex.DecodeString(lateCorrupt)
	var strict rrc.RRCConnectionSetupCompleteV8a0IEs
	strictErr := strict.UnmarshalUPER(wire)
	if !errors.Is(strictErr, per.ErrTruncated) {
		t.Fatalf("Eager error = %v", strictErr)
	}
	options, log := deferring(per.DeferOnError)
	var value rrc.RRCConnectionSetupCompleteV8a0IEs
	if err := value.UnmarshalUPERWithOptions(wire, options); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 || records[0].Path != "RRCConnectionSetupCompleteV8a0IEs.LateNonCriticalExtension" || records[0].Kind != per.OctetStringContainer || records[0].BitLength != 8 || records[0].Err.Error() != strictErr.Error() {
		t.Fatalf("records = %+v; Eager error %v", records, strictErr)
	}
	d := value.LateNonCriticalExtension.PERPadding_.Deferred()
	if d == nil || !bytes.Equal(d.Bytes(), []byte{0x80}) || d.Err() != records[0].Err {
		t.Fatalf("deferred = %+v", d)
	}
	if out, err := value.MarshalUPER(); err != nil || !bytes.Equal(out, wire) {
		t.Fatalf("re-encode = %x, %v", out, err)
	}
	var later rrc.RRCConnectionSetupCompleteV8x0IEs
	if err := later.UnmarshalUPERWithOptions(d.Bytes(), per.DecodeOptions{}); !errors.Is(err, per.ErrTruncated) {
		t.Fatalf("later decode error = %v", err)
	}

	edited := value
	shell := *value.LateNonCriticalExtension
	shell.LateNonCriticalExtension = []byte{1}
	edited.LateNonCriticalExtension = &shell
	if _, err := edited.MarshalUPER(); !errors.Is(err, per.ErrEditedDeferred) {
		t.Fatalf("edited shell: %v", err)
	}
	replaced := value
	replaced.LateNonCriticalExtension = &rrc.RRCConnectionSetupCompleteV8x0IEs{}
	if out, err := replaced.MarshalUPER(); err != nil || hex.EncodeToString(out) != lateValid {
		t.Fatalf("replaced = %x, %v", out, err)
	}
}

// DeferAll decodes no contained value; the later decode through
// UnmarshalUPERWithOptions gives the Eager value.
func TestDeferAllLateNonCriticalExtension(t *testing.T) {
	wire, _ := hex.DecodeString(lateValid)
	var strict rrc.RRCConnectionSetupCompleteV8a0IEs
	if err := strict.UnmarshalUPER(wire); err != nil {
		t.Fatal(err)
	}
	options, log := deferring(per.DeferAll)
	var value rrc.RRCConnectionSetupCompleteV8a0IEs
	if err := value.UnmarshalUPERWithOptions(wire, options); err != nil {
		t.Fatal(err)
	}
	if records := log.Snapshot(); len(records) != 1 || records[0].Err != nil {
		t.Fatalf("records = %+v", records)
	}
	if out, err := value.MarshalUPER(); err != nil || !bytes.Equal(out, wire) {
		t.Fatalf("re-encode = %x, %v", out, err)
	}
	var later rrc.RRCConnectionSetupCompleteV8x0IEs
	if err := later.UnmarshalUPERWithOptions(value.LateNonCriticalExtension.PERPadding_.Deferred().Bytes(), per.DecodeOptions{}); err != nil {
		t.Fatal(err)
	}
	value.LateNonCriticalExtension = &later
	if !reflect.DeepEqual(value, strict) {
		t.Fatalf("later decode %+v, Eager %+v", value, strict)
	}
}

// The contained interRATHandoverInfo-r3-add-ext value is two bits (194020).
// Senders that pad it to an octet inside its BIT STRING (19408000, ...)
// violate X.691 (02/2021) 11.1.3.2; pycrate 0.7.11 decodes the same value
// from each input. Without TrailingBitsTolerance, DeferOnError keeps only
// that contained value raw (TS 36.331 V19.4.0 8.1).
func TestDeferOnErrorKeepsPaddedInterRATHandoverInfoR3AddExt(t *testing.T) {
	const path = "InterRATHandoverInfo.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions.InterRATHandoverInfoR3AddExt"
	for _, tc := range []struct {
		input string
		bits  int
		raw   string
	}{
		{"19408000", 8, "00"},
		{"19408200", 8, "20"},
		{"1940c000", 12, "0000"},
		{"1940c201", 12, "2010"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			input, _ := hex.DecodeString(tc.input)
			var strict umts.InterRATHandoverInfo
			strictErr := strict.UnmarshalUPER(input)
			if !errors.Is(strictErr, per.ErrExtraData) {
				t.Fatalf("Eager error = %v", strictErr)
			}
			var deferrals per.DeferralLog
			var value umts.InterRATHandoverInfo
			if err := value.UnmarshalUPERWithOptions(input, per.DecodeOptions{ContainedDecoding: per.DeferOnError, Deferrals: &deferrals}); err != nil {
				t.Fatal(err)
			}
			records := deferrals.Snapshot()
			if len(records) != 1 || records[0].Path != path || records[0].Kind != per.BitStringContainer || records[0].BitLength != tc.bits || records[0].Err.Error() != strictErr.Error() {
				t.Fatalf("records = %+v; Eager error %v", records, strictErr)
			}
			host := value.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions
			d := host.InterRATHandoverInfoR3AddExt.PERPadding_.Deferred()
			if d == nil || d.BitLength() != tc.bits || hex.EncodeToString(d.Bytes()) != tc.raw {
				t.Fatalf("deferred = %+v", d)
			}
			if out, err := value.MarshalUPER(); err != nil || !bytes.Equal(out, input) {
				t.Fatalf("re-encode = %x, %v", out, err)
			}
			// The later decode through the bit buffer fails alike, and with
			// tolerance gives the tolerant Eager value.
			bb, err := d.BitBuffer(per.DecodeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var later umts.InterRATHandoverInfoR3AddExtIEs
			if err := later.UnmarshalUPERFrom(bb); err != nil {
				t.Fatal(err)
			}
			if _, err := per.CaptureDeferredBits(bb, "InterRATHandoverInfoR3AddExtIEs"); !errors.Is(err, per.ErrExtraData) {
				t.Fatalf("later decode error = %v", err)
			}
			var tolerated per.ToleranceLog
			options := per.DecodeOptions{TrailingBitsTolerance: &tolerated}
			var tolerant umts.InterRATHandoverInfo
			if err := tolerant.UnmarshalUPERWithOptions(input, options); err != nil {
				t.Fatal(err)
			}
			if bb, err = d.BitBuffer(options); err != nil {
				t.Fatal(err)
			}
			if err := later.UnmarshalUPERFrom(bb); err != nil {
				t.Fatal(err)
			}
			padding, err := per.CaptureDeferredBits(bb, "InterRATHandoverInfoR3AddExtIEs")
			if err != nil {
				t.Fatal(err)
			}
			host.InterRATHandoverInfoR3AddExt, host.InterRATHandoverInfoR3AddExtPERPadding_ = &later, padding
			if !reflect.DeepEqual(value, tolerant) {
				t.Fatalf("later decode %+v, tolerant Eager %+v", value, tolerant)
			}
		})
	}
}

// DeferAll keeps the canonical two-bit value raw; its later decode equals
// the Eager value.
func TestDeferAllInterRATHandoverInfo(t *testing.T) {
	input, _ := hex.DecodeString("194020")
	var strict umts.InterRATHandoverInfo
	if err := strict.UnmarshalUPER(input); err != nil {
		t.Fatal(err)
	}
	var deferrals per.DeferralLog
	var value umts.InterRATHandoverInfo
	if err := value.UnmarshalUPERWithOptions(input, per.DecodeOptions{ContainedDecoding: per.DeferAll, Deferrals: &deferrals}); err != nil {
		t.Fatal(err)
	}
	if records := deferrals.Snapshot(); len(records) != 1 || records[0].BitLength != 2 || records[0].Err != nil {
		t.Fatalf("records = %+v", records)
	}
	if out, err := value.MarshalUPER(); err != nil || !bytes.Equal(out, input) {
		t.Fatalf("re-encode = %x, %v", out, err)
	}
	host := value.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions
	bb, err := host.InterRATHandoverInfoR3AddExt.PERPadding_.Deferred().BitBuffer(per.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var later umts.InterRATHandoverInfoR3AddExtIEs
	if err := later.UnmarshalUPERFrom(bb); err != nil {
		t.Fatal(err)
	}
	if host.InterRATHandoverInfoR3AddExtPERPadding_, err = per.CaptureDeferredBits(bb, "InterRATHandoverInfoR3AddExtIEs"); err != nil {
		t.Fatal(err)
	}
	host.InterRATHandoverInfoR3AddExt = &later
	if !reflect.DeepEqual(value, strict) {
		t.Fatalf("later decode %+v, Eager %+v", value, strict)
	}
}
