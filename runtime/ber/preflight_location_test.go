package ber

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type elementLocation interface {
	Offset() int
	ChildIndexes() []int
}

// Error locations are codec diagnostics. Wire rejection follows X.690
// (02/2021) §§8.1.2–8.1.5 and §8.3.1 (nonempty INTEGER contents).
func TestBERPreflightErrorLocation(t *testing.T) {
	for _, test := range []struct {
		name, wire, message string
		offset              int
		indexes             []int
		cause               error
		options             []DecodeOption
	}{
		{name: "empty third integer", wire: "30080201010201020200", offset: 8, indexes: []int{2}, cause: ErrInvalidValue, message: "ber: invalid value encoding: X.690 (02/2021) §8.3.1 requires INTEGER contents"},
		{name: "truncated third integer", wire: "30080201010201020201", offset: 8, indexes: []int{2}, cause: ErrTruncated, message: ErrTruncated.Error()},
		{name: "nested numbers", wire: "300aa0080201010201020200", offset: 10, indexes: []int{0, 2}, cause: ErrInvalidValue, message: "ber: invalid value encoding: X.690 (02/2021) §8.3.1 requires INTEGER contents"},
		{name: "non-final bits definite", wire: "23080302018003020000", offset: 2, indexes: []int{0}, cause: ErrInvalidValue, message: "ber: invalid value encoding: non-final BIT STRING segment has unused bits"},
		{name: "non-final bits nested", wire: "300a23080302018003020000", offset: 4, indexes: []int{0, 0}, cause: ErrInvalidValue},
		{name: "non-final bits indefinite", wire: "238003020180030200000000", offset: 2, indexes: []int{0}, cause: ErrInvalidValue},
		{name: "non-final bits nested indefinite", wire: "30802380030201800302000000000000", offset: 4, indexes: []int{0, 0}, cause: ErrInvalidValue},
		{name: "non-final constructed bits", wire: "230a23040302018003020000", offset: 2, indexes: []int{0}, cause: ErrInvalidValue},
		{name: "non-final indefinite constructed bits", wire: "23802380030201800000030200000000", offset: 2, indexes: []int{0}, cause: ErrInvalidValue},
		{name: "indefinite third", wire: "308002010102010202000000", offset: 8, indexes: []int{2}, cause: ErrInvalidValue},
		{name: "indefinite nested", wire: "3080a080020101020102020000000000", offset: 10, indexes: []int{0, 2}, cause: ErrInvalidValue},
		{name: "nested empty after sibling", wire: "300c050030080201010201020200", offset: 12, indexes: []int{1, 2}, cause: ErrInvalidValue},
		{name: "truncated tag", wire: "300205001f", offset: 4, cause: ErrExtraData},
		{name: "child truncated tag", wire: "30031f8100", offset: 2, indexes: []int{0}, cause: ErrTruncated},
		{name: "child invalid tag", wire: "30021f00", offset: 2, indexes: []int{0}, cause: ErrInvalidTag},
		{name: "child invalid length", wire: "300204ff", offset: 2, indexes: []int{0}, cause: ErrInvalidLength},
		{name: "segment tag", wire: "30052c030c0141", offset: 4, indexes: []int{0, 0}, cause: ErrInvalidTag},
		{name: "constructed UTF8", wire: "30052c030401ff", offset: 2, indexes: []int{0}, cause: ErrInvalidValue},
		{name: "missing nested EOC", wire: "30800500a080020101", offset: 4, indexes: []int{1}, cause: ErrTruncated},
		{name: "missing root EOC", wire: "30800500", offset: 0, cause: ErrTruncated},
		{name: "depth", wire: "30023000", offset: 2, indexes: []int{0}, cause: ErrResourceLimit, options: []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 1})}},
		{name: "elements", wire: "300405000500", offset: 4, indexes: []int{1}, cause: ErrResourceLimit, options: []DecodeOption{WithDecodeLimits(DecodeLimits{MaxElements: 2})}},
		{name: "root empty", wire: "", offset: 0, cause: ErrTruncated, message: ErrTruncated.Error()},
		{name: "root trailing", wire: "05000500", offset: 2, cause: ErrExtraData, message: ErrExtraData.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateBERElement(structureWire(t, test.wire), test.options...)
			if !errors.Is(err, test.cause) {
				t.Fatalf("cause %v want %v", err, test.cause)
			}
			if test.message != "" && err.Error() != test.message {
				t.Fatalf("message %q want %q", err.Error(), test.message)
			}
			var located elementLocation
			if !errors.As(err, &located) {
				t.Fatalf("missing BER element location: %v", err)
			}
			if located.Offset() != test.offset || !reflect.DeepEqual(located.ChildIndexes(), test.indexes) {
				t.Fatalf("offset=%d indexes=%v want %d %v", located.Offset(), located.ChildIndexes(), test.offset, test.indexes)
			}
			indexes := located.ChildIndexes()
			if len(indexes) > 0 {
				indexes[0] = 99
				if !reflect.DeepEqual(located.ChildIndexes(), test.indexes) {
					t.Fatal("caller mutated error ancestry")
				}
			}
		})
	}
}

// X.690 (02/2021) §§8.6.4.1, 8.7.3.2, 8.23.3: BIT STRING
// fragments use tag 3; all other constructed string fragments use tag 4.
func TestBERPreflightStringFragmentLocations(t *testing.T) {
	for _, number := range []byte{3, 4, 7, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30} {
		fragment := []byte{4, 1, 'A'}
		if number == 3 {
			fragment = []byte{3, 2, 0, 0x80}
		}
		for bad := range 3 {
			for _, indefinite := range []bool{false, true} {
				for _, nested := range []bool{false, true} {
					t.Run(fmt.Sprintf("tag%d/fragment%d/indefinite%t/nested%t", number, bad, indefinite, nested), func(t *testing.T) {
						var contents []byte
						for index := range 3 {
							if index == bad {
								contents = append(contents, 5, 0) // NULL cannot be a string fragment.
							} else {
								contents = append(contents, fragment...)
							}
						}
						wire := locationConstructed(number|0x20, contents, indefinite)
						offset, indexes := 2+bad*len(fragment), []int{bad}
						if nested {
							wire = locationConstructed(0x30, wire, indefinite)
							offset += 2
							indexes = append([]int{0}, indexes...)
						}
						assertFragmentLocation(t, wire, ErrInvalidTag, offset, indexes)
					})
				}
			}
		}
	}
}

// X.690 (02/2021) §§8.6.2.2–8.6.2.3, 8.6.4: invalid contents
// locate their own fragment; non-final unused bits locate the previous segment,
// including a constructed segment whose final child supplied its unused count.
func TestBERPreflightBitStringFragmentLocations(t *testing.T) {
	for _, fault := range []string{"count", "empty", "non-final"} {
		for bad := range 3 {
			if fault == "non-final" && bad == 2 {
				continue // The last fragment may have unused bits.
			}
			for _, form := range []string{"primitive", "constructed", "indefinite"} {
				for _, indefinite := range []bool{false, true} {
					for _, nested := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/fragment%d/%s/indefinite%t/nested%t", fault, bad, form, indefinite, nested), func(t *testing.T) {
							var contents []byte
							wantOffset := 2
							for index := range 3 {
								fragment := []byte{3, 2, 0, 0x80}
								if index == bad {
									switch fault {
									case "count":
										fragment[2] = 8
									case "empty":
										fragment = []byte{3, 0}
									case "non-final":
										fragment[2] = 1
									}
									wantOffset += len(contents)
								}
								if form != "primitive" {
									fragment = locationConstructed(0x23, fragment, form == "indefinite")
								}
								contents = append(contents, fragment...)
							}
							wire := locationConstructed(0x23, contents, indefinite)
							indexes := []int{bad}
							if form != "primitive" && fault != "non-final" {
								wantOffset += 2
								indexes = append(indexes, 0)
							}
							if nested {
								wire = locationConstructed(0x30, wire, indefinite)
								wantOffset += 2
								indexes = append([]int{0}, indexes...)
							}
							assertFragmentLocation(t, wire, ErrInvalidValue, wantOffset, indexes)
						})
					}
				}
			}
		}
	}
}

func locationConstructed(identifier byte, contents []byte, indefinite bool) []byte {
	wire := []byte{identifier, byte(len(contents))}
	if indefinite {
		wire[1] = 0x80
	}
	wire = append(wire, contents...)
	if indefinite {
		wire = append(wire, 0, 0)
	}
	return wire
}

func assertFragmentLocation(t *testing.T, wire []byte, cause error, offset int, indexes []int) {
	t.Helper()
	err := ValidateBERElement(wire)
	var located *ElementError
	if !errors.Is(err, cause) || !errors.As(err, &located) {
		t.Fatalf("%x: unexpected error %v", wire, err)
	}
	if located.Offset() != offset || !reflect.DeepEqual(located.ChildIndexes(), indexes) {
		t.Fatalf("%x: offset=%d indexes=%v want %d %v", wire, located.Offset(), located.ChildIndexes(), offset, indexes)
	}
}

func TestBERPreflightInvalidOptionsHaveNoLocation(t *testing.T) {
	err := ValidateBERElement(structureWire(t, "30020500"), nil)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatal(err)
	}
	var located elementLocation
	if errors.As(err, &located) {
		t.Fatal("option error was labelled as a wire failure")
	}
}

func FuzzBERPreflightLocation(f *testing.F) {
	for _, s := range []string{"30080201010201020200", "30080201010201020201", "300aa0080201010201020200", "30800500a080020101", "30031f8100", "0500"} {
		f.Add(structureWire(f, s))
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		err := ValidateBERElement(wire, WithDecodeLimits(DecodeLimits{MaxDepth: 8, MaxElements: 32, MaxWork: 4096}))
		if err == nil {
			return
		}
		var located elementLocation
		if !errors.As(err, &located) {
			t.Fatalf("missing wire location: %v", err)
		}
		if located.Offset() < 0 || located.Offset() > len(wire) {
			t.Fatalf("offset %d outside input", located.Offset())
		}
		if len(located.ChildIndexes()) > 9 {
			t.Fatal("ancestry exceeds nesting bound")
		}
		for _, index := range located.ChildIndexes() {
			if index < 0 || index >= 32 {
				t.Fatalf("invalid child index %d", index)
			}
		}
	})
}
