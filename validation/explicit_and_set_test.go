package validation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/esim/sgp22"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

type berValue interface {
	UnmarshalBER([]byte, ...ber.DecodeOption) error
	MarshalBER(...ber.EncodeOption) ([]byte, error)
	MarshalDER() ([]byte, error)
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rejectsTrailingInExplicit checks that wire, whose EXPLICIT wrapper holds a
// complete base encoding followed by more octets, is rejected with
// ber.ErrExtraData in strict and in tolerant decoding (ITU-T X.690 (02/2021)
// §8.14.3: the contents of an explicitly tagged value are exactly one
// complete encoding of the base value).
func rejectsTrailingInExplicit(t *testing.T, name string, fresh func() berValue, wire []byte) {
	t.Helper()
	if err := fresh().UnmarshalBER(wire); !errors.Is(err, ber.ErrExtraData) {
		t.Fatalf("%s strict decode error = %v, want ber.ErrExtraData", name, err)
	}
	var violations ber.ViolationLog
	if err := fresh().UnmarshalBER(wire, ber.WithConstraintTolerance(&violations)); !errors.Is(err, ber.ErrExtraData) {
		t.Fatalf("%s tolerant decode error = %v, want ber.ErrExtraData", name, err)
	}
	if reports := violations.Snapshot(); len(reports) != 0 {
		t.Fatalf("%s tolerant decode reported %+v", name, reports)
	}
}

func replaysExactly(t *testing.T, name string, value berValue, wire []byte) {
	t.Helper()
	if err := value.UnmarshalBER(wire); err != nil {
		t.Fatalf("%s decode: %v", name, err)
	}
	for kind, encode := range map[string]func() ([]byte, error){
		"BER": func() ([]byte, error) { return value.MarshalBER() },
		"DER": value.MarshalDER,
	} {
		if out, err := encode(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%s %s = %x, %v; want %x", name, kind, out, err, wire)
		}
	}
}

// TCAP AARQ-apdu ([APPLICATION 0]) with application-context-name in
// [1] EXPLICIT. pycrate 0.7.11 encodes {application-context-name 0.4.0.0.1.0.1.3}
// as 600ba109060704000001000103. The second form adds a NULL (0500) after the
// OBJECT IDENTIFIER inside [1]; earlier releases accepted it and dropped
// the extra octets.
func TestExplicitWrapperRejectsTrailingAARQ(t *testing.T) {
	valid := mustHex(t, "600ba109060704000001000103")
	var request tcap.AARQApdu
	replaysExactly(t, "AARQ-apdu", &request, valid)
	if want := (runtime.ObjectIdentifier{0, 4, 0, 0, 1, 0, 1, 3}); !request.ApplicationContextName.Equal(want) {
		t.Fatalf("application-context-name = %v, want %v", request.ApplicationContextName, want)
	}
	rejectsTrailingInExplicit(t, "AARQ-apdu", func() berValue { return &tcap.AARQApdu{} },
		mustHex(t, "600da10b0607040000010001030500"))
}

// X.509 TBSCertificate with version [0] EXPLICIT Version v3 (RFC 5280
// Appendix A.1), an empty issuer and subject, and an EC public key. pycrate
// 0.7.11 produces the DER below. The second form adds a NULL (0500) after
// the INTEGER inside [0].
func TestExplicitWrapperRejectsTrailingTBSCertificateVersion(t *testing.T) {
	const tail = "020101300a06082a8648ce3d0403023000301e170d3236303130313030303030305a170d3336303130313030303030305a3000300f300906072a8648ce3d020103020004"
	valid := mustHex(t, "3049a003020102"+tail)
	var certificate sgp22.TBSCertificate
	replaysExactly(t, "TBSCertificate", &certificate, valid)
	if certificate.Version == nil {
		t.Fatal("version absent")
	}
	if name, ok := certificate.Version.Name(); !ok || name != "v3" {
		t.Fatalf("version = %v", certificate.Version)
	}
	rejectsTrailingInExplicit(t, "TBSCertificate", func() berValue { return &sgp22.TBSCertificate{} },
		mustHex(t, "304ba0050201020500"+tail))
}

// PKIX PersonalName is a SET (RFC 5280 Appendix A.1). A decoded value keeps
// its received bytes only when it needs them: here, when the components
// arrive out of schema order (X.690 (02/2021) §8.11.2 lets a BER sender
// choose the order). Both forms replay byte-exactly; DER sorts the components
// (§10.3). pycrate 0.7.11 decodes all three vectors to the same values and
// encodes their DER in schema order.
func TestPersonalNameSetOrder(t *testing.T) {
	for _, tc := range []struct {
		wire, der string
		given     bool
	}{
		{"310380014a", "310380014a", false},
		{"3106800141810142", "3106800141810142", true},
		{"3106810142800141", "3106800141810142", true},
	} {
		wire := mustHex(t, tc.wire)
		var name sgp22.PersonalName
		if err := name.UnmarshalBER(wire); err != nil {
			t.Fatalf("%s: %v", tc.wire, err)
		}
		if (name.GivenName != nil) != tc.given {
			t.Fatalf("%s: given-name = %v", tc.wire, name.GivenName)
		}
		if out, err := name.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%s: BER = %x, %v", tc.wire, out, err)
		}
		if out, err := name.MarshalDER(); err != nil || hex.EncodeToString(out) != tc.der {
			t.Fatalf("%s: DER = %x, %v; want %s", tc.wire, out, err, tc.der)
		}
	}
	// A value in schema order keeps no received copy, so its decode
	// allocates clearly less than a reordered one, which must keep its bytes.
	// The bound is relative, not an exact count.
	inOrder, reordered := mustHex(t, "3106800141810142"), mustHex(t, "3106810142800141")
	allocations := func(wire []byte) float64 {
		return testing.AllocsPerRun(100, func() {
			var name sgp22.PersonalName
			_ = name.UnmarshalBER(wire)
		})
	}
	if a, b := allocations(inOrder), allocations(reordered); a >= b {
		t.Fatalf("decode allocations: schema order %v, reordered %v; want fewer in schema order", a, b)
	}
}
