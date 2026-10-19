// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/hardening_test.go; SHA-256 93745662efa8ce2e3fdae238e7ff35ad3ed4596c7d622433e049efad65cb805f.
package ber

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	goruntime "runtime"
	"testing"

	rt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestRejectionBeforeReplayAllocation(t *testing.T) {
	for _, elements := range []int{1000, 10000, 100000} {
		input := append([]byte{0x30, 0x80}, bytes.Repeat([]byte{0x30, 0x80, 0, 0}, elements)...)
		input = append(input, 0, 0)
		for _, proof := range []bool{false, true} {
			opts := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxElements: 3})}
			if proof {
				opts = append(opts, ForceGeneratedBERProofForTesting())
			}
			opts = TrackBERForm(opts)
			goruntime.GC()
			var before, after goruntime.MemStats
			goruntime.ReadMemStats(&before)
			owned, err := OwnGeneratedBERInput(input, opts)
			if err == nil {
				_, _, err = PrepareGeneratedBERInput(owned, opts)
			}
			goruntime.ReadMemStats(&after)
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatal("missing element refusal", err)
			}
			used := after.TotalAlloc - before.TotalAlloc
			if used > 128<<10 {
				t.Fatalf("elements=%d proof=%v rejection allocated %d; limit 128 KiB", elements, proof, used)
			}
		}
	}
}

func TestSegmentedStringWorkOnce(t *testing.T) {
	for _, kind := range []int{tag.TagOctetString, tag.TagBitString} {
		for _, depth := range []int{0, 1, 10, 50} {
			contents := bytes.Repeat([]byte{0x80}, 1024)
			if kind == tag.TagBitString {
				contents = append([]byte{0}, contents...)
			}
			data, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: kind}, contents)
			if err != nil {
				t.Fatal(err)
			}
			for range depth {
				data, err = EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: kind, Constructed: true}, data)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, limit := range []int{len(data), len(data) - 1} {
				options := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 200, MaxWork: limit})}
				validateErr := ValidateBERElement(data, options...)
				budget, budgetErr := newBERWorkBudget(options)
				if budgetErr != nil {
					t.Fatal(budgetErr)
				}
				var decoded []byte
				_, _, decodeErr := decodeStringSegments(data, kind, 0, &budget, &decoded)
				if limit == len(data) {
					if validateErr != nil || decodeErr != nil {
						t.Fatalf("kind%d depth%d len%d: validator=%v decoder=%v", kind, depth, len(data), validateErr, decodeErr)
					}
					continue
				}
				var a, b *ElementError
				if !errors.Is(validateErr, ErrResourceLimit) || !errors.Is(decodeErr, ErrResourceLimit) || !errors.As(validateErr, &a) || !errors.As(decodeErr, &b) || a.Offset() != b.Offset() || !reflect.DeepEqual(a.ChildIndexes(), b.ChildIndexes()) {
					t.Fatalf("kind%d depth%d: validation=%v decode=%v; locations %+v %+v", kind, depth, validateErr, decodeErr, a, b)
				}
			}
		}
	}
}

func TestMaxWorkFailureLocation(t *testing.T) {
	data := []byte{0x62, 8, 0x48, 4, 1, 2, 3, 4, 0x6c, 0}
	err := ValidateBERElement(data, WithDecodeLimits(DecodeLimits{MaxWork: 8}))
	var located *ElementError
	if !errors.Is(err, ErrResourceLimit) || !errors.As(err, &located) || located.Offset() != 8 || !reflect.DeepEqual(located.ChildIndexes(), []int{1}) {
		t.Fatalf("want offset8 child[1], got %+v: %v", located, err)
	}
}

func TestDelimiterIndependentOfLengthForm(t *testing.T) {
	for _, data := range [][]byte{{0x30, 2, 0x25, 0}, {0x30, 0x80, 0x25, 0, 0, 0}, {0x30, 4, 0xa0, 2, 0x25, 0}, {0x30, 0x80, 0xa0, 0x80, 0x25, 0, 0, 0, 0, 0}} {
		_, n, _, err := DecodeTLV(data)
		if err != nil || n != len(data) {
			t.Fatalf("delimiter rejected nested constructed NULL %x: %v", data, err)
		}
		if err = ValidateBERElement(data); !errors.Is(err, ErrInvalidTag) {
			t.Fatalf("validator accepted constructed NULL: %v", err)
		}
	}
}

func TestFreshBitStringNormalization(t *testing.T) {
	data := []byte{0xff}
	encoded, err := EncodeBitString(data, 7)
	if err != nil || !bytes.Equal(encoded, []byte{3, 2, 7, 0x80}) || data[0] != 0xff {
		t.Fatalf("BIT STRING %x input%x: %v", encoded, data, err)
	}
	value, err := EncodeBitStringValue(data, 7)
	if err != nil || !bytes.Equal(value, []byte{7, 0x80}) || data[0] != 0xff {
		t.Fatalf("BIT STRING value %x input%x: %v", value, data, err)
	}
	ext := rt.External{DirectReference: rt.MustObjectIdentifierFromArcs(1, 2, 3), Encoding: rt.ExternalArbitrary, Arbitrary: rt.BitString{Bytes: data, BitLength: 1}}
	for _, der := range []bool{false, true} {
		if der {
			encoded, err = EncodeExternalDER(ext)
		} else {
			encoded, err = EncodeExternal(ext)
		}
		if err != nil || !bytes.HasSuffix(encoded, []byte{0x82, 2, 7, 0x80}) || data[0] != 0xff {
			t.Fatalf("EXTERNAL der%v %x input%x: %v", der, encoded, data, err)
		}
	}
}

func TestIntegerObservationsStayBounded(t *testing.T) {
	for _, size := range []int{1024, 8192, 65536} {
		value := new(big.Int).Lsh(big.NewInt(1), uint(size*8-1))
		goruntime.GC()
		var before, after goruntime.MemStats
		goruntime.ReadMemStats(&before)
		observation := ObserveInteger(value)
		goruntime.ReadMemStats(&after)
		if len(observation) > 128 || after.TotalAlloc-before.TotalAlloc > uint64(4*size+8192) {
			t.Fatalf("%d input bytes: observation=%d allocation=%d", size, len(observation), after.TotalAlloc-before.TotalAlloc)
		}
		other := new(big.Int).Add(value, big.NewInt(1))
		if observation == ObserveInteger(other) || observation == ObserveInteger(new(big.Int).Neg(value)) {
			t.Fatal("distinct wide observations collapsed")
		}
	}
}

func TestAncestryRetainsOnlyTargetPath(t *testing.T) {
	for _, count := range []int{1000, 10000, 99998} {
		body := bytes.Repeat([]byte{5, 0}, count)
		input, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}, body)
		if err != nil {
			t.Fatal(err)
		}
		origin := decodeOrigin{root: input, limits: DefaultDecodeLimits()}
		goruntime.GC()
		var before, after goruntime.MemStats
		goruntime.ReadMemStats(&before)
		indexes, locateErr := origin.ancestry(len(input) - 2)
		if locateErr != nil {
			t.Fatal(locateErr)
		}
		goruntime.ReadMemStats(&after)
		if !reflect.DeepEqual(indexes, []int{count - 1}) {
			t.Fatalf("count%d path%v", count, indexes)
		}
		if used := after.TotalAlloc - before.TotalAlloc; used > 32<<10 {
			t.Fatalf("count%d ancestry allocated %d bytes", count, used)
		}
	}
}

func TestAncestryManyRecordsLinearWork(t *testing.T) {
	for _, count := range []int{1000, 10000, 90000} {
		const records = 1000
		input, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}, bytes.Repeat([]byte{5, 0}, count+records))
		if err != nil {
			t.Fatal(err)
		}
		origin := decodeOrigin{root: input, limits: DefaultDecodeLimits()}
		for index := range records {
			offset := len(input) - 2*(records-index)
			if indexes, err := origin.ancestry(offset); err != nil || !reflect.DeepEqual(indexes, []int{count + index}) {
				t.Fatalf("target %d: %v", index, indexes)
			}
		}
		if origin.ancestryVisits > 2*(count+records+1) {
			t.Fatalf("prefix %d records %d: %d header visits exceeds linear bound %d", count, records, origin.ancestryVisits, 2*(count+records+1))
		}
	}
}

func TestAncestryWorkBudgetAndCachedLocations(t *testing.T) {
	input := []byte{0x30, 6, 5, 0, 5, 0, 5, 0}
	origin := decodeOrigin{root: input, limits: DecodeLimits{MaxDepth: 10, MaxElements: 10, MaxWork: 4}}
	for _, offset := range []int{2, 4, 2, 4} {
		indexes, err := origin.ancestry(offset)
		if err != nil || !reflect.DeepEqual(indexes, []int{(offset - 2) / 2}) {
			t.Fatalf("offset%d: %v %v", offset, indexes, err)
		}
		if len(indexes) > 0 {
			indexes[0] = 99
		}
	}
	if origin.ancestryVisits != 2 || origin.search.work != 4 {
		t.Fatalf("cached lookups charged more work: visits%d work%d", origin.ancestryVisits, origin.search.work)
	}
	_, err := origin.ancestry(6)
	var element *ElementError
	if !errors.Is(err, ErrResourceLimit) || !errors.As(err, &element) || element.Offset() != 4 || !reflect.DeepEqual(element.ChildIndexes(), []int{1}) {
		t.Fatalf("budget location: %v", err)
	}
}

// Ordinary validation must keep the fixed scan frames on the stack, even
// though ancestry searches can suspend and retain their own copy of the path.
