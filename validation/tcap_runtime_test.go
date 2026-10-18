package validation

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
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
			options = append(options, ber.WithTolerance(&log))
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
		option := ber.WithTolerance(&log)
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

// go-asn1 #160; Q.773 (06/1997) §4.1.1 requires the short length form below
// 128 octets. A standalone value decoded tolerantly keeps its received form for
// replay, but strict encoding and validation refuse it and return no bytes.
func TestStandaloneStrictEncodeRefusesToleratedLength(t *testing.T) {
	received := mustHex(t, "02810101")
	var decodeLog ber.ViolationLog
	var value tcap.TCInvokeIdSet
	if err := value.UnmarshalBER(received, ber.WithTolerance(&decodeLog)); err != nil {
		t.Fatal(err)
	}
	reports := decodeLog.Snapshot()
	if len(reports) != 1 {
		t.Fatalf("decode reported %+v, want one violation", reports)
	}
	wire, err := value.MarshalBER()
	var refusal *ber.ValidationError
	if wire != nil || !errors.As(err, &refusal) || !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatalf("strict MarshalBER = %x, %v", wire, err)
	}
	if refusal.Rule != reports[0].Rule {
		t.Fatalf("strict rule %+v, decode rule %+v", refusal.Rule, reports[0].Rule)
	}
	if err := value.Validate(); !errors.As(err, &refusal) {
		t.Fatalf("strict Validate: %v", err)
	}
	var encodeLog ber.ViolationLog
	if wire, err := value.MarshalBER(ber.WithTolerance(&encodeLog)); err != nil || !bytes.Equal(wire, received) {
		t.Fatalf("tolerant MarshalBER = %x, %v", wire, err)
	}
	if reports := encodeLog.Snapshot(); len(reports) != 1 {
		t.Fatalf("encode reported %+v, want one violation", reports)
	}
	canonical := tcap.NewTCInvokeIdSetPresentInt64(1)
	if wire, err := canonical.MarshalBER(); err != nil || !bytes.Equal(wire, mustHex(t, "020101")) {
		t.Fatalf("canonical MarshalBER = %x, %v", wire, err)
	}
}

// go-asn1 #168: after an edit, strict encoding of a tolerantly decoded message
// rebuilds the parts whose received form Q.773 (06/1997) §4.1.1 forbids,
// instead of refusing them.
func TestEditedTolerantMessageEncodesCanonically(t *testing.T) {
	want := mustHex(t, "620d4801076c08a10602010102012e")
	for _, received := range []string{"620e4801016c09a1810602010102012e", "620e4801016c8108a10602010102012e"} {
		var value tcap.TCMessage
		var log ber.ViolationLog
		if err := value.UnmarshalBER(mustHex(t, received), ber.WithTolerance(&log)); err != nil {
			t.Fatal(err)
		}
		if len(log.Snapshot()) == 0 {
			t.Fatalf("%s: tolerant decode reported no violation", received)
		}
		value.Begin.Otid[0] = 7
		if wire, err := value.MarshalBER(); err != nil || !bytes.Equal(wire, want) {
			t.Fatalf("%s: strict MarshalBER = %x, %v", received, wire, err)
		}
		if err := value.Validate(); err != nil {
			t.Fatalf("%s: strict Validate: %v", received, err)
		}
	}
}

// tcapTLV builds a short-form BER TLV from hex parts.
func tcapTLV(id string, parts ...string) string {
	content := strings.Join(parts, "")
	return fmt.Sprintf("%s%02x%s", id, len(content)/2, content)
}

func decodeErrorOf(t *testing.T, err error) *tcap.DecodeError {
	t.Helper()
	var decodeErr *tcap.DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("error %v is not a *tcap.DecodeError", err)
	}
	return decodeErr
}

// go-asn1 #161, #162: DecodeError.Prefix keeps the transaction IDs that the
// decoder accepted under the active options, whatever fails later. A receiver
// needs the OTID to abort the transaction (Q.774 (06/1997) §3.2.2.1).
func TestDecodeErrorPrefixKeepsAcceptedTransactionIDs(t *testing.T) {
	for _, tc := range []struct{ name, wire, otid, dtid string }{
		{"Continue, failing Invoke", "650d4801014901026c05a103020105", "01", "02"},
		{"Continue without its DTID", "650a4801016c05a103020105", "01", ""},
		{"unrecognized [APPLICATION 6]", "660a4801016c05a103020105", "01", ""},
	} {
		var message tcap.TCMessage
		prefix := decodeErrorOf(t, message.UnmarshalBER(mustHex(t, tc.wire))).Prefix
		if prefix.Otid == nil || !bytes.Equal(*prefix.Otid, mustHex(t, tc.otid)) {
			t.Fatalf("%s: Prefix.Otid = %v, want %s", tc.name, prefix.Otid, tc.otid)
		}
		if gotDtid := prefix.Dtid != nil; gotDtid != (tc.dtid != "") || gotDtid && !bytes.Equal(*prefix.Dtid, mustHex(t, tc.dtid)) {
			t.Fatalf("%s: Prefix.Dtid = %v, want %q", tc.name, prefix.Dtid, tc.dtid)
		}
	}
	// Q.773 §4.1.1 and the SIZE (1..4) constraint refuse these OTIDs strictly;
	// tolerant decoding accepts them, so its Prefix carries them.
	for _, tc := range []struct{ otid, accepted string }{
		{"6803040101", "01"}, {"48050102030405", "0102030405"}, {"4800", ""},
	} {
		wire := mustHex(t, tcapTLV("62", tc.otid, "6c05a103020105"))
		var log ber.ViolationLog
		var tolerant tcap.TCMessage
		prefix := decodeErrorOf(t, tolerant.UnmarshalBER(wire, ber.WithTolerance(&log))).Prefix
		if prefix.Otid == nil || !bytes.Equal(*prefix.Otid, mustHex(t, tc.accepted)) {
			t.Fatalf("%x tolerant: Prefix.Otid = %v, want %q", wire, prefix.Otid, tc.accepted)
		}
		var strict tcap.TCMessage
		if prefix := decodeErrorOf(t, strict.UnmarshalBER(wire)).Prefix; prefix.Otid != nil {
			t.Fatalf("%x strict: Prefix.Otid = %x for a refused OTID", wire, *prefix.Otid)
		}
	}
}

// go-asn1 #163: Q.774 (06/1997) §3.2.2.1 discards the components of a message
// whose dialogue portion is incorrect, so its Q.773 §4.2.3 violation is
// reported before a component error.
func TestDialoguePortionErrorPrecedesComponentError(t *testing.T) {
	audt := "6b142812060700118605010201a0076005a10306012a"
	for _, components := range []string{"6c08a106020105020102", "6c05a103020105"} {
		var message tcap.TCMessage
		err := message.UnmarshalBER(mustHex(t, tcapTLV("62", "480101", audt, components)))
		var refusal *ber.ValidationError
		if path := decodeErrorOf(t, err).Path; path != "begin.dialoguePortion" || !errors.As(err, &refusal) {
			t.Fatalf("components %s: path %q, error %v", components, path, err)
		}
		if !strings.HasSuffix(err.Error(), "structured-no-unidialogue-syntax") {
			t.Fatalf("components %s: incomplete message %q", components, err)
		}
	}
	var message tcap.TCMessage
	err := message.UnmarshalBER(mustHex(t, "620a4801016c05a103020105"))
	if path := decodeErrorOf(t, err).Path; path != "begin.components.element[0].basicROS.invoke" {
		t.Fatalf("without a dialogue portion: path %q, error %v", path, err)
	}
}

// go-asn1 #164: X.690 (02/2021) §8.9.3 lets BER encode a component equal to
// its DEFAULT, and a set field asks for it; only DER and CER omit it (§11.5).
func TestFreshBERKeepsExplicitDefault(t *testing.T) {
	acn := runtime.MustObjectIdentifier("0.4.0.0.1.0.19.3")
	version1 := tcap.AARQApduProtocolVersionDefault()
	implicit := mustHex(t, "600ba109060704000001001303")
	explicit := mustHex(t, "600f80020780a109060704000001001303")
	for _, tc := range []struct {
		version *runtime.BitString
		ber     []byte
	}{{nil, implicit}, {&version1, explicit}} {
		pdu := tcap.NewDialoguePDUDialogueRequest(tcap.AARQApdu{ProtocolVersion: tc.version, ApplicationContextName: acn})
		for name, encode := range map[string]func() ([]byte, error){
			"BER":              func() ([]byte, error) { return pdu.MarshalBER() },
			"WithoutBERReplay": func() ([]byte, error) { return pdu.MarshalBER(ber.WithoutBERReplay()) },
		} {
			if wire, err := encode(); err != nil || !bytes.Equal(wire, tc.ber) {
				t.Fatalf("version set %v, %s = %x, %v; want %x", tc.version != nil, name, wire, err, tc.ber)
			}
		}
		if wire, err := pdu.MarshalDER(); err != nil || !bytes.Equal(wire, implicit) {
			t.Fatalf("version set %v, DER = %x, %v", tc.version != nil, wire, err)
		}
	}
}

// go-asn1 #165: the dialogue portion follows each message's procedure. A Begin
// carries the AARQ APDU (Q.774 (06/1997) Figure A.5, sheet 3) and a
// Unidirectional the AUDT APDU (Q.773 (06/1997) §4.2.3, Q.771 §2.3.1.2.1), so
// another abstract syntax is refused strictly and reported under tolerance.
// Continue (Q.774 §3.2.1.2), End and Abort (Q.773 §3.1) may carry it.
func TestDialogueSyntaxFollowsMessageProcedure(t *testing.T) {
	userSyntax := "6b0b280906022a03a003020101"
	invoke := "6c08a106020105020102"
	for _, tc := range []struct {
		name, wire string
		refused    bool
	}{
		{"Begin", tcapTLV("62", "480101", userSyntax, invoke), true},
		{"Unidirectional", tcapTLV("61", userSyntax, invoke), true},
		{"Continue", tcapTLV("65", "480101", "490102", userSyntax, invoke), false},
		{"End", tcapTLV("64", "490102", userSyntax, invoke), false},
		{"Abort", tcapTLV("67", "490102", userSyntax), false},
	} {
		wire := mustHex(t, tc.wire)
		var strict tcap.TCMessage
		err := strict.UnmarshalBER(wire)
		if tc.refused {
			var refusal *ber.ValidationError
			if !errors.As(err, &refusal) || !strings.HasSuffix(decodeErrorOf(t, err).Path, ".dialoguePortion") {
				t.Fatalf("%s: strict decode = %v, want a dialogue-portion refusal", tc.name, err)
			}
			var log ber.ViolationLog
			var tolerant tcap.TCMessage
			if err := tolerant.UnmarshalBER(wire, ber.WithTolerance(&log)); err != nil || len(log.Snapshot()) != 1 {
				t.Fatalf("%s: tolerant decode = %v, reports %+v", tc.name, err, log.Snapshot())
			}
			if out, err := tolerant.MarshalBER(ber.WithTolerance(new(ber.ViolationLog))); err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("%s: tolerant replay = %x, %v", tc.name, out, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: strict decode: %v", tc.name, err)
		}
		if out, err := strict.MarshalBER(); err != nil || !bytes.Equal(out, wire) {
			t.Fatalf("%s: replay = %x, %v", tc.name, out, err)
		}
	}
}

// go-asn1 #166: a dialogue portion refused for indirect-only identification
// (Q.773 (06/1997) §4.2.3, X.690 (02/2021) §8.18.4) is located at the dialogue
// portion, element 1 of the Begin at message offset 5, so Prefix keeps the OTID.
func TestIndirectOnlyDialogueErrorIsLocated(t *testing.T) {
	var message tcap.TCMessage
	err := message.UnmarshalBER(mustHex(t, "620c4801016b0728050201008100"))
	decodeErr := decodeErrorOf(t, err)
	if decodeErr.Path != "begin.dialoguePortion.identification" {
		t.Fatalf("path %q, error %v", decodeErr.Path, err)
	}
	if otid := decodeErr.Prefix.Otid; otid == nil || !bytes.Equal(*otid, mustHex(t, "01")) {
		t.Fatalf("Prefix.Otid = %v", otid)
	}
	var element *ber.ElementError
	if !errors.As(err, &element) || element.Offset() != 5 || !reflect.DeepEqual(element.ChildIndexes(), []int{1}) {
		t.Fatalf("element location of %v", err)
	}
}
