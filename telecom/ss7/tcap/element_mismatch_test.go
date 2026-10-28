package tcap

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// X.680 (02/2021) §§25.6, 29 and X.690 (02/2021) §§8.1, 8.3, 8.9, 8.18.
func TestElementMismatchAndImplicitIntegerContents(t *testing.T) {
	for _, tc := range []struct {
		wire, path   string
		decode, scan error
	}{
		{"62074801016b020500", "begin.dialoguePortion", ber.ErrUnexpectedElement, nil},
		{"650648027f010500", "continue", ber.ErrUnexpectedElement, nil},
		{"67054901016a00", "abort.reason.AbortReason.p-abortCause", ber.ErrInvalidTag, ber.ErrInvalidTag},
		{"62054801014c00", "begin.components", ber.ErrInvalidTag, nil},
		{"62054801016b00", "begin.dialoguePortion", ber.ErrUnexpectedElement, nil},
		{"620c4801016b07280506012a8300", "begin.dialoguePortion", ber.ErrUnexpectedElement, nil},
		{"620b48027f016c05a10302010a", "begin.components.element[0].basicROS.invoke", ber.ErrUnexpectedElement, nil},
		{"67054901014a00", "abort.reason.p-abortCause", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"67074901014a020001", "abort.reason.p-abortCause", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"640f4901016c0aa108020101800002012d", "end.components.element[0].basicROS.invoke.linkedId.present", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"670449004a00", "abort.dtid", ber.ErrInvalidValue, ber.ErrInvalidValue},
		{"620648027f010500", "begin", ber.ErrUnexpectedElement, nil},
		{"6200", "begin", ber.ErrUnexpectedElement, nil},
		{"620448027f0100", "TCMessage", ber.ErrExtraData, ber.ErrExtraData},
		{"6800", "TCMessage", ber.ErrUnexpectedElement, nil},
		{"6100", "unidirectional", ber.ErrUnexpectedElement, nil},
		{"3000", "TCMessage", ber.ErrUnexpectedElement, nil},
		{"6204", "TCMessage", ber.ErrTruncated, ber.ErrTruncated},
		{"6280", "TCMessage", ber.ErrTruncated, ber.ErrTruncated},
		{"62ff", "TCMessage", ber.ErrInvalidLength, ber.ErrInvalidLength},
		{"1f8000", "TCMessage", ber.ErrInvalidTag, ber.ErrInvalidTag},
		{"1000", "TCMessage", ber.ErrInvalidTag, ber.ErrInvalidTag},
		{"4200", "TCMessage.begin", ber.ErrInvalidTag, nil},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			var value TCMessage
			decoded := value.UnmarshalBER(data)
			var failure *DecodeError
			if !errors.As(decoded, &failure) || failure.Path != tc.path {
				t.Fatalf("path: %v, want %s", decoded, tc.path)
			}
			scan := ber.ValidateBERElement(data, ber.TrackTCAPForm(nil)...)
			if tc.scan == nil && scan != nil {
				t.Fatalf("profile scan = %v, want nil", scan)
			}
			for _, check := range []struct {
				name      string
				got, want error
			}{{"decode", decoded, tc.decode}, {"scan", scan, tc.scan}} {
				t.Run(check.name, func(t *testing.T) {
					for _, sentinel := range []error{ber.ErrUnexpectedElement, ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
						if errors.Is(check.got, sentinel) != (sentinel == check.want) {
							t.Errorf("%v: errors.Is(%v)=%t, want %t", check.got, sentinel, errors.Is(check.got, sentinel), sentinel == check.want)
						}
					}
				})
			}
		})
	}
}

func TestProfileKeepsNonIntegerPrimitiveContents(t *testing.T) {
	// X.690 (02/2021) §8.7.1 admits an empty OCTET STRING. The
	// transaction identifier is [APPLICATION 8] IMPLICIT OCTET STRING.
	wire, err := hex.DecodeString("62024800")
	if err != nil {
		t.Fatal(err)
	}
	if err := ber.ValidateBERElement(wire, ber.TrackTCAPForm(nil)...); err != nil {
		t.Fatal(err)
	}
}

// X.690 (02/2021) §§8.1.2–8.1.3, 8.3.1, 8.14.3, 8.18.1.
func TestExplicitWrappersAndIntegerForms(t *testing.T) {
	for _, tc := range []struct {
		wire, path   string
		decode, scan error
	}{
		{"62204801016b1b2819060700118605010101a00e600ba10906070400000100130305", "child[1].child[0].child[1].child[1]", ber.ErrTruncated, ber.ErrTruncated},
		{"62124801016b0d280b060700118605010101a000", "begin.dialoguePortion", ber.ErrUnexpectedElement, nil},
		{"620d4801016b08280606022a03a000", "begin.dialoguePortion", ber.ErrUnexpectedElement, nil},
		{"670449006a00", "abort.dtid", ber.ErrInvalidValue, ber.ErrInvalidTag},
		{"670749006a03020100", "abort.dtid", ber.ErrInvalidValue, ber.ErrInvalidTag},
		{"62124801016c0da10b020101a00302010002012d", "begin.components.element[0].basicROS.invoke.linkedId.InvokeLinkedId.present", ber.ErrInvalidTag, ber.ErrInvalidTag},
		{"640f4901016c0aa408020101a003020100", "end.components.element[0].basicROS.reject.problem.RejectProblemChoice.general", ber.ErrInvalidTag, ber.ErrInvalidTag},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			wire, e := hex.DecodeString(tc.wire)
			if e != nil {
				t.Fatal(e)
			}
			var v TCMessage
			err := v.UnmarshalBER(wire)
			var failure *DecodeError
			if !errors.As(err, &failure) || failure.Path != tc.path {
				t.Fatalf("decode=%v; path want %s", err, tc.path)
			}
			assertBERErrors(t, err, tc.decode)
			assertBERErrors(t, ber.ValidateBERElement(wire, ber.TrackTCAPForm(nil)...), tc.scan)
		})
	}
	for _, tc := range []struct {
		root, wire, path string
		value            interface {
			UnmarshalBER([]byte, ...ber.DecodeOption) error
		}
		want error
	}{
		{"DialoguePDU", "6114a109060704000001001303a200a305a103020100", "dialogueResponse.result", new(DialoguePDU), ber.ErrUnexpectedElement},
		{"DialoguePDU", "6002a100", "dialogueRequest.application-context-name", new(DialoguePDU), ber.ErrUnexpectedElement},
		{"AbortReason", "4a00", "p-abortCause", new(AbortReason), ber.ErrInvalidValue},
		{"RejectProblemChoice", "8000", "general", new(RejectProblemChoice), ber.ErrInvalidValue},
	} {
		t.Run(tc.root+"/"+tc.wire, func(t *testing.T) {
			wire, e := hex.DecodeString(tc.wire)
			if e != nil {
				t.Fatal(e)
			}
			err := tc.value.UnmarshalBER(wire)
			assertBERErrors(t, err, tc.want)
			var located interface{ ASN1BERPath() string }
			if !errors.As(err, &located) || located.ASN1BERPath() != tc.path {
				t.Fatalf("decode=%v; path want %s", err, tc.path)
			}
			var scanWant error
			if tc.want == ber.ErrInvalidValue {
				scanWant = tc.want
			}
			assertBERErrors(t, ber.ValidateBERElement(wire, ber.TrackTCAPForm(nil, tc.root)...), scanWant)
		})
	}
}

func assertBERErrors(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("error=%v, want %v", got, want)
	}
	for _, sentinel := range []error{ber.ErrUnexpectedElement, ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
		if errors.Is(got, sentinel) != (want == sentinel) {
			t.Errorf("%v: errors.Is(%v)=%t, want %t", got, sentinel, errors.Is(got, sentinel), want == sentinel)
		}
	}
}

// X.690 (02/2021) §§8.1.2–8.1.4, 8.14.3, 8.18.1: the emitted
// runtime retains the compiler runtime's classification of EXTERNAL contents.
func TestStandaloneExternalSentinelClassification(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want error
	}{
		{"280906022a03a003050005", ber.ErrTruncated},
		{"280b06022a03a00505001f8000", ber.ErrInvalidTag},
		{"280a06022a03a00405000500", ber.ErrUnexpectedElement},
		{"280606022a03a000", ber.ErrUnexpectedElement},
		{"280706022a03a00105", ber.ErrTruncated},
		{"2800", ber.ErrInvalidValue},
		{"280b06022a03a0050500300105", ber.ErrTruncated},
		{"280a06022a03a00405002200", ber.ErrInvalidTag},
		{"2819060700118605010101a00e600ba10906070400000100130305", ber.ErrTruncated},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = ber.DecodeExternal(wire)
			assertBERErrors(t, err, tc.want)
			_, err = ber.DecodeExternalValue(wire[2:])
			assertBERErrors(t, err, tc.want)
			scanWant := tc.want
			if scanWant == ber.ErrUnexpectedElement || scanWant == ber.ErrInvalidValue {
				scanWant = nil
			}
			assertBERErrors(t, ber.ValidateBERElement(wire, ber.TrackTCAPForm(nil, "External")...), scanWant)
		})
	}
}
