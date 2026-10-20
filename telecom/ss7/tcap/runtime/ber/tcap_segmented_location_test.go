// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_segmented_location_test.go; SHA-256 654e24fa5c4eb684bd1324ccb26d4a7348c289eab26b56abac22f263715a34ff.
package ber

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"reflect"
	"testing"
)

func locationTLV(t testing.TB, id byte, body []byte, indefinite bool) []byte {
	t.Helper()
	if indefinite {
		return append(append([]byte{id, 0x80}, body...), 0, 0)
	}
	wire, err := EncodeTLV(tag.Tag{Class: tag.Class(id >> 6), Constructed: id&32 != 0, Number: int(id & 31)}, body)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func locationDialogue(t testing.TB, choice byte, contents []byte) []byte {
	t.Helper()
	external := locationTLV(t, 0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, contents...), false)
	if choice != 0 {
		external = locationTLV(t, 0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, locationTLV(t, choice, contents, false)...), false)
	}
	return locationTLV(t, 0x62, append([]byte{0x48, 1, 1}, locationTLV(t, 0x6b, external, false)...), false)
}

func structuralLocation(t *testing.T, wire []byte, tolerant bool) *ElementError {
	t.Helper()
	var log ViolationLog
	var options []DecodeOption
	if tolerant {
		options = append(options, WithTolerance(&log))
	}
	err := ValidateBERElement(wire, TrackTCAPForm(options, "TCMessage")...)
	var located *ElementError
	if !errors.As(err, &located) {
		t.Fatalf("missing ElementError: %v", err)
	}
	return located
}

// Q.773 (06/1997) §§3.2, 4.2.3; X.690 (02/2021) §§8.6.4,
// 8.7.3, 8.18.10–8.18.11. String boundaries carry no APDU semantics.
func TestTCAPSegmentedStructuralLocationVectors(t *testing.T) {
	for _, row := range []struct {
		name, hex string
		offset    int
	}{
		{"primitive", "62274801016b22282006070011860501010181156013a07f03020780a10b06092b0601040183b20302", 22},
		{"two-segments", "622b4801016b262824060700118605010101a119040160041413a07f03020780a10b06092b0601040183b20302", 26},
	} {
		t.Run(row.name, func(t *testing.T) {
			wire, err := hex.DecodeString(row.hex)
			if err != nil {
				t.Fatal(err)
			}
			located := structuralLocation(t, wire, true)
			if !errors.Is(located, ErrTruncated) || located.Offset() != row.offset || !reflect.DeepEqual(located.ChildIndexes(), []int{1, 0, 1, 0, 0}) {
				t.Fatalf("location = %d %v: %v", located.Offset(), located.ChildIndexes(), located)
			}
		})
	}
}

// The identifier's FIRST physical octet is reported even when the remaining
// identifier or length octets occur in another segment. The ancestry below
// the EXTERNAL choice is logical, matching the primitive control.
func TestTCAPSegmentedStructuralLocationEveryBoundary(t *testing.T) {
	for _, header := range [][]byte{{0xa0, 0x7f}, {0x85, 0x82, 1, 0}, {0xbf, 0x81, 0x7f, 0x7f}, {0xa0, 4, 3, 0x7f}} {
		apdu := locationTLV(t, 0x60, append(append([]byte(nil), header...), []byte{3, 2, 7, 0x80, 0xa1, 0x0b, 6, 9, 0x2b, 6, 1, 4, 1, 0x83, 0xb2, 3, 2}...), false)
		target := 2
		if header[1] == 4 {
			// The malformed BIT STRING is nested within protocol-version.
			target = 4
		}
		for _, bit := range []bool{false, true} {
			primitive := byte(0x81)
			primitiveBody := apdu
			id := byte(4)
			if bit {
				primitive, id = 0x82, 3
				primitiveBody = append([]byte{0}, apdu...)
			}
			primitiveWire := locationDialogue(t, primitive, primitiveBody)
			control := structuralLocation(t, primitiveWire, true)
			indexes := []int{1, 0, 1, 0, 0}
			if target == 4 {
				indexes = append(indexes, 0)
			}
			if !errors.Is(control, ErrTruncated) || control.Offset() != len(primitiveWire)-len(apdu)+target || !reflect.DeepEqual(control.ChildIndexes(), indexes) {
				t.Fatalf("primitive control: %d %v: %v", control.Offset(), control.ChildIndexes(), control)
			}
			if header[0] != 0xa0 {
				strict := structuralLocation(t, primitiveWire, false)
				if !errors.Is(strict, ErrTruncated) || strict.Offset() != control.Offset() || !reflect.DeepEqual(strict.ChildIndexes(), indexes) {
					t.Fatalf("strict primitive control: %d %v: %v", strict.Offset(), strict.ChildIndexes(), strict)
				}
			}
			for _, nested := range []bool{false, true} {
				for _, indefinite := range []bool{false, true} {
					// cut=0 uses one-octet leaves; the rest exercise every split.
					for cut := 0; cut < len(apdu); cut++ {
						t.Run(fmt.Sprintf("header=%x/bits=%t/nested=%t/indefinite=%t/cut=%d", header, bit, nested, indefinite, cut), func(t *testing.T) {
							var segments []byte
							logical, physical := 0, -1
							leaf := func(payload []byte) {
								size := len(payload)
								if bit {
									payload = append([]byte{0}, payload...)
								}
								out := locationTLV(t, id, payload, false)
								start := len(out) - size
								if nested {
									wrapper := locationTLV(t, id|0x20, out, indefinite)
									start += len(wrapper) - len(out) - 2*btoi(indefinite)
									out = wrapper
								}
								if logical <= target && target < logical+size {
									physical = len(segments) + start + target - logical
								}
								logical += size
								segments = append(segments, out...)
							}
							if cut == 0 {
								for _, octet := range apdu {
									leaf([]byte{octet})
								}
							} else {
								leaf(apdu[:cut])
								leaf(apdu[cut:])
							}
							choice := locationTLV(t, primitive|0x20, segments, indefinite)
							wire := locationDialogue(t, 0, choice)
							located := structuralLocation(t, wire, true)
							// The enclosing envelopes are definite, with the choice last.
							// Compute provenance from the builder's lengths, independently
							// of the runtime's offset map and ancestry scanner.
							want := len(wire) - len(segments) - 2*btoi(indefinite) + physical
							if !errors.Is(located, ErrTruncated) || located.Offset() != want || !reflect.DeepEqual(located.ChildIndexes(), control.ChildIndexes()) {
								t.Fatalf("location = %d %v: %v; want %d %v", located.Offset(), located.ChildIndexes(), located, want, control.ChildIndexes())
							}
							// Strict policy still refuses the constructed carriage first.
							strict := structuralLocation(t, wire, false)
							var profile *ValidationError
							if !errors.As(strict, &profile) || strict.Offset() != len(wire)-len(choice) || !reflect.DeepEqual(strict.ChildIndexes(), []int{1, 0, 1}) {
								t.Fatalf("strict carriage refusal changed: %d %v: %v", strict.Offset(), strict.ChildIndexes(), strict)
							}
							if physical < 0 || wire[want] != apdu[target] {
								t.Fatal("wrong physical identifier")
							}
						})
					}
				}
			}
		}
	}
}

// X.690 (02/2021) §8.1.2.4.2 and Erratum 1 (09/2021, Figure 4):
// a high-tag identifier needs a terminating octet. Its first physical octet
// identifies the failure even if subsequent octets occupy different segments.
func TestTCAPSegmentedRootIdentifierLocation(t *testing.T) {
	for _, apdu := range [][]byte{{0x7f}, {0x7f, 0x81}, {0x7f, 0x81, 0x81}} {
		for _, bit := range []bool{false, true} {
			primitive, id := byte(0x81), byte(4)
			body := apdu
			if bit {
				primitive, id = 0x82, 3
				body = append([]byte{0}, apdu...)
			}
			primitiveWire := locationDialogue(t, primitive, body)
			control := structuralLocation(t, primitiveWire, true)
			indexes := []int{1, 0, 1, 0}
			if !errors.Is(control, ErrTruncated) || control.Offset() != len(primitiveWire)-len(apdu) || !reflect.DeepEqual(control.ChildIndexes(), indexes) {
				t.Fatalf("primitive control: %d %v: %v", control.Offset(), control.ChildIndexes(), control)
			}
			strict := structuralLocation(t, primitiveWire, false)
			if !errors.Is(strict, ErrTruncated) || strict.Offset() != control.Offset() || !reflect.DeepEqual(strict.ChildIndexes(), indexes) {
				t.Fatalf("strict primitive control: %d %v: %v", strict.Offset(), strict.ChildIndexes(), strict)
			}
			for _, nested := range []bool{false, true} {
				for _, indefinite := range []bool{false, true} {
					for cut := 0; cut < len(apdu); cut++ {
						t.Run(fmt.Sprintf("apdu=%x/bits=%t/nested=%t/indefinite=%t/cut=%d", apdu, bit, nested, indefinite, cut), func(t *testing.T) {
							var segments []byte
							first := -1
							leaf := func(payload []byte) {
								size := len(payload)
								if bit {
									payload = append([]byte{0}, payload...)
								}
								out := locationTLV(t, id, payload, false)
								start := len(out) - size
								if nested {
									wrapper := locationTLV(t, id|0x20, out, indefinite)
									start += len(wrapper) - len(out) - 2*btoi(indefinite)
									out = wrapper
								}
								if first < 0 {
									first = start
								}
								segments = append(segments, out...)
							}
							if cut == 0 {
								for _, octet := range apdu {
									leaf([]byte{octet})
								}
							} else {
								leaf(apdu[:cut])
								leaf(apdu[cut:])
							}
							choice := locationTLV(t, primitive|0x20, segments, indefinite)
							wire := locationDialogue(t, 0, choice)
							want := len(wire) - len(segments) - 2*btoi(indefinite) + first
							located := structuralLocation(t, wire, true)
							if !errors.Is(located, ErrTruncated) || located.Offset() != want || !reflect.DeepEqual(located.ChildIndexes(), control.ChildIndexes()) {
								t.Fatalf("location = %d %v: %v; want %d %v", located.Offset(), located.ChildIndexes(), located, want, control.ChildIndexes())
							}
							if !bit && !nested && !indefinite && len(apdu) == 1 {
								if hex.EncodeToString(wire) != "62154801016b10280e060700118605010101a10304017f" || want != 22 {
									t.Fatal("root identifier reproducer changed")
								}
							}
							strict := structuralLocation(t, wire, false)
							var profile *ValidationError
							if !errors.As(strict, &profile) || strict.Offset() != len(wire)-len(choice) || !reflect.DeepEqual(strict.ChildIndexes(), []int{1, 0, 1}) {
								t.Fatalf("strict carriage refusal changed: %d %v: %v", strict.Offset(), strict.ChildIndexes(), strict)
							}
						})
					}
				}
			}
		}
	}
}

func BenchmarkTCAPStructuralLocationValid(b *testing.B) {
	apdu, err := hex.DecodeString("600da10b06092b0601040183b20302")
	if err != nil {
		b.Fatal(err)
	}
	for _, row := range []struct {
		name     string
		wire     []byte
		tolerant bool
	}{
		{"generic", []byte{0x30, 3, 2, 1, 1}, false},
		{"primitive-octets", locationDialogue(b, 0x81, apdu), false},
		{"primitive-bits", locationDialogue(b, 0x82, append([]byte{0}, apdu...)), false},
		{"segmented-octets", locationDialogue(b, 0xa1, append(locationTLV(b, 4, apdu[:1], false), locationTLV(b, 4, apdu[1:], false)...)), true},
	} {
		b.Run(row.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var log ViolationLog
				var options []DecodeOption
				if row.tolerant {
					options = append(options, WithTolerance(&log))
				}
				if err := ValidateBERElement(row.wire, TrackTCAPForm(options, "TCMessage")...); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
