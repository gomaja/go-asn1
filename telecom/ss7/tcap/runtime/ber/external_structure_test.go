// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/external_structure_test.go; SHA-256 efdfd4c48f8a9fc8ce17bed273f6298ddba8e8cfb9e7d699ba0f4cc6bb143e2d.
package ber

import (
	"bytes"
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"reflect"
	"testing"
)

// X.690 (02/2021) §§8.9.2, 8.18.1, 8.18.9: an open value still
// consists of complete BER encodings, including its constructed contents.
func TestExternalSingleASN1Structure(t *testing.T) {
	for _, text := range []string{
		"280b060130a006300430303030",
		"2809060130a00430020501",
		"2809060130a00430020000",
		"2809060130a00430020200",
		"280b020101a006300430303030",
		"280e060130020101a006300430303030",
		"2811060130020101070141a006300430303030",
		"2880060130a08030043030303000000000",
		"28810c060130a08106300430303030",
	} {
		wire := structureWire(t, text)
		for _, tolerant := range []bool{false, true} {
			var reports ViolationLog
			var options []DecodeOption
			if tolerant {
				options = []DecodeOption{WithTolerance(&reports)}
			}
			want := ValidateBERElement(wire, options...)
			if want == nil {
				t.Fatal("malformed control passed validation")
			}
			_, n, got := DecodeExternal(wire, options...)
			if n != 0 {
				t.Fatalf("malformed EXTERNAL consumed %d bytes", n)
			}
			assertExternalStructureError(t, got, want)
			// The implicit entry point reports offsets in its contents. Its child
			// positions are the same as the universal EXTERNAL's child positions.
			_, _, contents, framingErr := DecodeTLV(wire)
			if framingErr != nil {
				t.Fatal(framingErr)
			}
			_, got = DecodeExternalValue(contents, options...)
			var expected *ElementError
			if !errors.As(want, &expected) {
				t.Fatalf("validator location missing: %v", want)
			}
			assertExternalStructureError(t, got, &ElementError{offset: expected.Offset() - externalStructureHeaderLength(t, wire), childIndexes: expected.ChildIndexes(), cause: expected.Unwrap()})
			if len(reports.Snapshot()) != 0 {
				t.Fatal("structural failure reported as tolerable")
			}
		}
	}
}

func assertExternalStructureError(t *testing.T, got, want error) {
	t.Helper()
	var a, b *ElementError
	if got == nil || !errors.As(got, &a) || !errors.As(want, &b) || got.Error() != want.Error() || !errors.Is(got, externalStructureCause(want)) || a.Offset() != b.Offset() || !reflect.DeepEqual(a.ChildIndexes(), b.ChildIndexes()) {
		t.Fatalf("error = %#v (%v), want %#v (%v)", got, got, want, want)
	}
}

func TestExternalNestedSingleASN1Replay(t *testing.T) {
	for _, text := range []string{
		"280b060130a006300430020500",
		"2880060130a0803080308005000000000000000000",
		"280c060130a00728050201018100",
	} {
		wire := structureWire(t, text)
		// Nested EXTERNAL values are opaque here; the structural validator
		// checks universal BER contents without claiming the nested schema.
		if err := ValidateBERElement(wire); err != nil {
			t.Fatal(err)
		}
		for _, tolerant := range []bool{false, true} {
			var reports ViolationLog
			var options []DecodeOption
			if tolerant {
				options = []DecodeOption{WithTolerance(&reports)}
			}
			value, n, err := DecodeExternal(wire, options...)
			if err != nil || n != len(wire) {
				t.Fatalf("decode: %d/%d %v", n, len(wire), err)
			}
			replay, err := EncodeExternal(value)
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay: %x %v", replay, err)
			}
		}
	}
}

func TestExternalValidatedSingleASN1DoesNotRescan(t *testing.T) {
	measure := func(depth int) float64 {
		inner := EncodeNull()
		for range depth {
			inner = mustEncode(t)(EncodeSequence(inner))
		}
		choice := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, inner))
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagExternal, Constructed: true}, append([]byte{2, 1, 1}, choice...)))
		options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
		owned, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(owned, options...); err != nil {
			t.Fatal(err)
		}
		owned, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		return testing.AllocsPerRun(10, func() {
			if _, n, err := DecodeExternal(owned, options...); err != nil || n != len(owned) {
				t.Fatalf("validated decode: %d %v", n, err)
			}
		})
	}
	shallow, deep := measure(2), measure(64)
	t.Logf("validated decode allocations: depth2=%g depth64=%g", shallow, deep)
	if deep > shallow {
		t.Fatalf("validated open value rescanned: shallow=%g deep=%g", shallow, deep)
	}
}

func externalStructureCause(err error) error {
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	return err
}

func externalStructureHeaderLength(t *testing.T, wire []byte) int {
	t.Helper()
	_, tagLength, err := DecodeTag(wire)
	if err != nil {
		t.Fatal(err)
	}
	_, _, lengthLength, err := DecodeLength(wire[tagLength:])
	if err != nil {
		t.Fatal(err)
	}
	return tagLength + lengthLength
}

// X.690 (02/2021) §§8.9.2, 8.18.1, 8.23.10: standalone open-value
// validation must retain the enclosing element's diagnostic coordinates.
func TestExternalWholeElementDiagnostics(t *testing.T) {
	for _, text := range []string{"280b060130a006300430303030", "2808060130a0030c01ff", "280a060130a00530030c01ff"} {
		for _, tolerant := range []bool{false, true} {
			for _, located := range []bool{false, true} {
				wire := structureWire(t, text)
				var control, actual ViolationLog
				opts := func(log *ViolationLog) []DecodeOption {
					var options []DecodeOption
					if tolerant {
						options = append(options, WithTolerance(log))
					}
					if located {
						options = LocateDecodedElement(wire, "Test.external", ChildDecodeOptions(options, "message"))
					}
					return options
				}
				want := ValidateBERElement(wire, opts(&control)...)
				_, _, got := DecodeExternal(wire, opts(&actual)...)
				if want != nil {
					assertExternalStructureError(t, got, want)
				} else if got != nil {
					t.Fatal(got)
				}
				if !reflect.DeepEqual(actual.Snapshot(), control.Snapshot()) {
					t.Fatalf("wire=%s tolerant=%t located=%t reports=%+v, want %+v", text, tolerant, located, actual.Snapshot(), control.Snapshot())
				}
			}
		}
	}
}

func TestExternalImplicitUTF8Diagnostics(t *testing.T) {
	for _, text := range []string{"2808060130a0030c01ff", "280a060130a00530030c01ff"} {
		wire := structureWire(t, text)
		_, _, contents, err := DecodeTLV(wire)
		if err != nil {
			t.Fatal(err)
		}
		var control, actual ViolationLog
		if err := ValidateBERElement(wire, WithTolerance(&control)); err != nil {
			t.Fatal(err)
		}
		want := control.Snapshot()
		for i := range want {
			if want[i].Offset != nil {
				*want[i].Offset -= externalStructureHeaderLength(t, wire)
			}
		}
		if _, err := DecodeExternalValue(contents, WithTolerance(&actual)); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual.Snapshot(), want) {
			t.Fatalf("reports=%+v, want %+v", actual.Snapshot(), want)
		}
	}
}

func TestExternalGeneratedModeScanAllocations(t *testing.T) {
	measure := func(depth int, mode DecodeOption) float64 {
		inner := EncodeNull()
		for range depth {
			inner = mustEncode(t)(EncodeSequence(inner))
		}
		choice := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, inner))
		wire := mustEncode(t)(EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagExternal, Constructed: true}, append([]byte{2, 1, 1}, choice...)))
		options := TrackBERForm([]DecodeOption{mode})
		owned, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(owned, options...); err != nil {
			t.Fatal(err)
		}
		owned, options, err = PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		return testing.AllocsPerRun(10, func() {
			if _, n, err := DecodeExternal(owned, options...); err != nil || n != len(owned) {
				t.Fatalf("validated decode: %d %v", n, err)
			}
		})
	}
	for _, mode := range []struct {
		name   string
		option DecodeOption
	}{
		{"adaptive", generatedModeOption{generatedModeAdaptive}},
		{"light", ForceGeneratedBERLightForTesting()},
		{"proof", ForceGeneratedBERProofForTesting()},
	} {
		t.Logf("mode=%s decode-only allocations: depth2=%g depth64=%g", mode.name, measure(2, mode.option), measure(64, mode.option))
	}
}
