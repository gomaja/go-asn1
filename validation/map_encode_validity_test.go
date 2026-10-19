package validation

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapber "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

// mapEncoder is the encode surface shared by generated GSM MAP values.
type mapEncoder interface {
	MarshalBER(...mapber.EncodeOption) ([]byte, error)
	MarshalDER() ([]byte, error)
}

// checkMAPEncodeRefusal requires strict BER, fresh BER and DER to refuse the
// value, and tolerant BER to emit want with exactly one record that matches
// the given decode record.
func checkMAPEncodeRefusal(t *testing.T, name string, value mapEncoder, want []byte, decoded mapber.Violation) {
	t.Helper()
	for mode, encode := range map[string]func() ([]byte, error){
		"strict BER": func() ([]byte, error) { return value.MarshalBER() },
		"fresh BER":  func() ([]byte, error) { return value.MarshalBER(mapber.WithoutBERReplay()) },
		"DER":        value.MarshalDER,
	} {
		if got, err := encode(); !errors.Is(err, mapber.ErrInvalidValue) {
			t.Errorf("%s: %s = %x, %v; want ErrInvalidValue", name, mode, got, err)
		}
	}
	var log mapber.ViolationLog
	got, err := value.MarshalBER(mapber.WithTolerance(&log))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s: tolerant BER = %x, %v; want %x", name, got, err, want)
	}
	records := log.Snapshot()
	if len(records) != 1 {
		t.Fatalf("%s: tolerant BER records = %+v; want one", name, records)
	}
	record := records[0]
	if record.Rule != decoded.Rule || record.Source != decoded.Source || record.Path != decoded.Path || record.Constraint != decoded.Constraint {
		t.Errorf("%s: encode record %+v does not match decode record %+v", name, record, decoded)
	}
	if record.Offset != nil || record.OctetOffset != nil || record.ChildIndexes != nil {
		t.Errorf("%s: encode record carries wire coordinates: %+v", name, record)
	}
}

// go-asn1 #182: X.690 (02/2021) §8.23.10 requires UTF8String contents to be
// valid UTF-8, and strict encoding must not emit what strict decoding
// refuses. h-gmlc-callBackUri is a [2] IMPLICIT UTF8String, so DER output
// checks cannot see the string type either.
func TestMAPUTF8StringEncodingRefusesInvalidText(t *testing.T) {
	wire := mustHex(t, "30068001018201ff")
	var strict gsm_map.LCSCancelDeferredLocationArg
	if err := strict.UnmarshalBER(wire); !errors.Is(err, mapber.ErrInvalidValue) {
		t.Fatalf("strict decode = %v; want ErrInvalidValue", err)
	}
	var decoded gsm_map.LCSCancelDeferredLocationArg
	var log mapber.ViolationLog
	if err := decoded.UnmarshalBER(wire, mapber.WithTolerance(&log)); err != nil {
		t.Fatalf("tolerant decode: %v", err)
	}
	records := log.Snapshot()
	if len(records) != 1 || records[0].Rule.Clause != "8.23.10" || records[0].Path != "h-gmlc-callBackUri" {
		t.Fatalf("tolerant decode records = %+v; want one §8.23.10 record at h-gmlc-callBackUri", records)
	}
	built := gsm_map.LCSCancelDeferredLocationArg{ReferenceNumberExt: []byte{0x01}, HGmlcCallBackUri: "\xff"}
	checkMAPEncodeRefusal(t, "caller-built", &built, wire, records[0])
	checkMAPEncodeRefusal(t, "tolerant decode", &decoded, wire, records[0])

	valid := gsm_map.LCSCancelDeferredLocationArg{ReferenceNumberExt: []byte{0x01}, HGmlcCallBackUri: "é"}
	if got, err := valid.MarshalDER(); err != nil || !bytes.Equal(got, mustHex(t, "30078001018202c3a9")) {
		t.Fatalf("valid text: MarshalDER = %x, %v; want 30078001018202c3a9", got, err)
	}
}

// go-asn1 #178: after a tolerant decode, strict encoding refuses a retained
// violation inside an unknown extension addition, as it refuses the same
// octet in the open extType field. Tolerant encoding still replays exactly
// and reports again (X.690 (02/2021) §8.23.10).
func TestMAPStrictEncodingRefusesRetainedOpaqueViolations(t *testing.T) {
	addition := mustHex(t, "300a8001018202f1210c01ff")
	var pdp gsm_map.PDPContextInfo
	if err := (&gsm_map.PDPContextInfo{}).UnmarshalBER(addition); !errors.Is(err, mapber.ErrInvalidValue) {
		t.Fatalf("PDPContextInfo strict decode = %v; want ErrInvalidValue", err)
	}
	var pdpLog mapber.ViolationLog
	if err := pdp.UnmarshalBER(addition, mapber.WithTolerance(&pdpLog)); err != nil {
		t.Fatalf("PDPContextInfo tolerant decode: %v", err)
	}
	if records := pdpLog.Snapshot(); len(records) != 1 {
		t.Fatalf("PDPContextInfo decode records = %+v; want one", records)
	} else {
		checkMAPEncodeRefusal(t, "PDPContextInfo unknown addition", &pdp, addition, records[0])
	}

	extension := mustHex(t, "300706022a030c01ff")
	var private gsm_map.PrivateExtension
	if err := (&gsm_map.PrivateExtension{}).UnmarshalBER(extension); !errors.Is(err, mapber.ErrInvalidValue) {
		t.Fatalf("PrivateExtension strict decode = %v; want ErrInvalidValue", err)
	}
	var privateLog mapber.ViolationLog
	if err := private.UnmarshalBER(extension, mapber.WithTolerance(&privateLog)); err != nil {
		t.Fatalf("PrivateExtension tolerant decode: %v", err)
	}
	if records := privateLog.Snapshot(); len(records) != 1 {
		t.Fatalf("PrivateExtension decode records = %+v; want one", records)
	} else {
		checkMAPEncodeRefusal(t, "PrivateExtension extType", &private, extension, records[0])
	}
}
