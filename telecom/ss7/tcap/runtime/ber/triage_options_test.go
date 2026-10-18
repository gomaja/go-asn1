// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/triage_options_test.go; SHA-256 8c00096c3f9d8ce49b9b6046524a05f325819d02d0a2582c33f66baa21e86a64.
package ber

import (
	"errors"
	"reflect"
	"testing"
)

func TestEmptyBEROptionsDoNotAllocate(t *testing.T) {
	wire := []byte{0x05, 0x00} // X.690 (02/2021) §8.8.2: NULL has no contents.
	if got := testing.AllocsPerRun(1000, func() {
		_, n, _, err := DecodeTLV(wire)
		if err != nil || n != len(wire) {
			panic("NULL decode failed")
		}
	}); got != 0 {
		t.Fatalf("empty DecodeTLV options: %g allocations, want 0", got)
	}
	if got := testing.AllocsPerRun(1000, func() {
		if err := ValidateEncodeOptions(); err != nil {
			panic(err)
		}
	}); got != 0 {
		t.Fatalf("empty encode options: %g allocations, want 0", got)
	}
	if _, _, _, err := DecodeTLV([]byte{0x05}); err == nil {
		t.Fatal("accepted truncated NULL")
	}
}

func TestBERConstraintPathsAreLazy(t *testing.T) {
	wire := []byte{0x05, 0x00}
	var decode []DecodeOption
	var encode []EncodeOption
	for _, component := range []string{"message", "components", "[3]", "invoke"} {
		decode = ChildDecodeOptions(decode, component)
		encode = ChildEncodeOptions(encode, component)
	}
	if got := testing.AllocsPerRun(1000, func() {
		_, _, _, err := DecodeTLV(wire, decode...)
		if err != nil {
			panic(err)
		}
	}); got > 1 {
		t.Fatalf("successful nested decode: %g allocations, want at most option config allocation", got)
	}
	if got := testing.AllocsPerRun(1000, func() {
		if err := ValidateEncodeOptions(encode...); err != nil {
			panic(err)
		}
	}); got > 1 {
		t.Fatalf("successful nested encode: %g allocations, want at most option config allocation", got)
	}
}

func TestBERFullConstraintPaths(t *testing.T) {
	for _, tolerant := range []bool{false, true} {
		var log ViolationLog
		var decode []DecodeOption
		var encode []EncodeOption
		if tolerant {
			policy := WithTolerance(&log)
			decode = []DecodeOption{policy}
			encode = []EncodeOption{policy}
		}
		for _, component := range []string{"message", "components", "[3]", "invoke"} {
			decode = ChildDecodeOptions(decode, component)
			encode = ChildEncodeOptions(encode, component)
		}
		for _, leaf := range []string{"id", ""} {
			want := "message.components.[3].invoke"
			if leaf != "" {
				want += "." + leaf
			}
			for _, err := range []error{
				CheckDecodedValue(decode, leaf, "(-128..127)", "128"),
				CheckEncodedValue(encode, leaf, "(-128..127)", "128"),
				CheckDecodedLength(decode, leaf, "SIZE (1)", 2),
				CheckEncodedLength(encode, leaf, "SIZE (1)", 2),
			} {
				if tolerant {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					var violation *ValidationError
					if !errors.As(err, &violation) || violation.Path != want {
						t.Fatalf("strict path: %v, want %s", err, want)
					}
				}
			}
		}
		if tolerant {
			records := log.Snapshot()
			if len(records) != 8 {
				t.Fatalf("reports = %d, want 8 separate direct-call violations", len(records))
			}
			for i, record := range records {
				want := "message.components.[3].invoke"
				if i < 4 {
					want += ".id"
				}
				if record.Path != want {
					t.Fatalf("report %d path = %s, want %s", i, record.Path, want)
				}
			}
		}
	}
}

func TestBERChildOptionsOwnTheirStorage(t *testing.T) {
	parentDecode := make([]DecodeOption, 0, 8)
	parentEncode := make([]EncodeOption, 0, 8)
	for _, component := range []string{"left", "right"} {
		decode := ChildDecodeOptions(parentDecode, component)
		encode := ChildEncodeOptions(parentEncode, component)
		var violation *ValidationError
		if err := CheckDecodedValue(decode, "id", "(0)", "1"); !errors.As(err, &violation) || violation.Path != component+".id" {
			t.Fatalf("decode child = %v", err)
		}
		if err := CheckEncodedValue(encode, "id", "(0)", "1"); !errors.As(err, &violation) || violation.Path != component+".id" {
			t.Fatalf("encode child = %v", err)
		}
	}
	if len(parentDecode) != 0 || len(parentEncode) != 0 {
		t.Fatal("child changed parent length")
	}
	if !reflect.DeepEqual(parentDecode[:cap(parentDecode)], make([]DecodeOption, cap(parentDecode))) || !reflect.DeepEqual(parentEncode[:cap(parentEncode)], make([]EncodeOption, cap(parentEncode))) {
		t.Fatal("child changed parent's spare storage")
	}
}

func TestBERCollectionPathsResetParentSizeCheck(t *testing.T) {
	decode := ParentCollectionSizeDecodeOptions(ChildDecodeOptions(nil, "items"))
	encode := ParentCollectionSizeEncodeOptions(ChildEncodeOptions(nil, "items"))
	if err := CheckDecodedCollectionLength(decode, "Items", "SIZE (1)", 2); err != nil {
		t.Fatal(err)
	}
	if err := CheckEncodedCollectionLength(encode, "Items", "SIZE (1)", 2); err != nil {
		t.Fatal(err)
	}
	var violation *ValidationError
	for _, err := range []error{
		CheckDecodedCollectionLength(ChildDecodeOptions(decode, "[2]"), "Items", "SIZE (1)", 2),
		CheckEncodedCollectionLength(ChildEncodeOptions(encode, "[2]"), "Items", "SIZE (1)", 2),
	} {
		if !errors.As(err, &violation) || violation.Path != "items.[2]" {
			t.Fatalf("nested collection check = %v", err)
		}
	}
	for _, err := range []error{
		CheckDecodedCollectionLength(nil, "Items", "SIZE (1)", 2),
		CheckEncodedCollectionLength(nil, "Items", "SIZE (1)", 2),
	} {
		if !errors.As(err, &violation) || violation.Path != "Items" {
			t.Fatalf("root collection check = %v", err)
		}
	}
}

func TestBERStagedNestedPathsRollback(t *testing.T) {
	for _, success := range []bool{false, true} {
		var log ViolationLog
		option := WithTolerance(&log)
		decode, finishDecode := StageDecodeReports([]DecodeOption{option})
		encode, finishEncode := StageEncodeReports([]EncodeOption{option})
		childDecode, childFinishDecode := StageDecodeReports(ChildDecodeOptions(decode, "child"))
		childEncode, childFinishEncode := StageEncodeReports(ChildEncodeOptions(encode, "child"))
		if err := CheckDecodedValue(childDecode, "field", "(0)", "1"); err != nil {
			t.Fatal(err)
		}
		if err := CheckEncodedValue(childEncode, "field", "(0)", "1"); err != nil {
			t.Fatal(err)
		}
		childFinishDecode(true)
		childFinishEncode(true)
		if len(log.Snapshot()) != 0 {
			t.Fatal("child published before parent committed")
		}
		finishDecode(success)
		finishEncode(success)
		records := log.Snapshot()
		if !success && len(records) != 0 {
			t.Fatal("failed parent published child reports")
		}
		if success && (len(records) != 2 || records[0].Path != "child.field" || records[1].Path != "child.field") {
			t.Fatalf("committed reports = %+v", records)
		}
	}
}

func BenchmarkBEROptions(b *testing.B) {
	for _, reporting := range []bool{false, true} {
		name := "strict"
		var decode []DecodeOption
		var encode []EncodeOption
		if reporting {
			name = "reporting"
			var log ViolationLog
			option := WithTolerance(&log)
			decode = []DecodeOption{option}
			encode = []EncodeOption{option}
		}
		for _, component := range []string{"message", "components", "[3]", "invoke"} {
			decode = ChildDecodeOptions(decode, component)
			encode = ChildEncodeOptions(encode, component)
		}
		b.Run(name+"/decode", func(b *testing.B) {
			wire := []byte{0x05, 0x00}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, _, err := DecodeTLV(wire, decode...); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"/encode", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := ValidateEncodeOptions(encode...); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestBERInvalidEncodePathsRemainRejected(t *testing.T) {
	for _, component := range []string{"", "bad.path"} {
		if err := ValidateEncodeOptions(ChildEncodeOptions(nil, component)...); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("encode path %q: %v", component, err)
		}
	}
}

// Path-only options must not change wire parsing or operational budgets.
func FuzzBEROptionPaths(f *testing.F) {
	f.Add([]byte{0x05, 0x00})
	f.Add([]byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00})
	f.Add([]byte{0x04, 0x81, 0x01, 0xaa})
	f.Add([]byte{0x05})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 2048 {
			return
		}
		base := []DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 8, MaxElements: 32, MaxWork: 4096})}
		nested := ChildDecodeOptions(ChildDecodeOptions(base, "items"), "[3]")
		bt, bn, bv, be := DecodeTLV(wire, base...)
		nt, nn, nv, ne := DecodeTLV(wire, nested...)
		if !reflect.DeepEqual(bt, nt) || bn != nn || !reflect.DeepEqual(bv, nv) || !sameOptionError(be, ne) {
			t.Fatalf("path changed TLV result: base=%v/%d/%x/%v nested=%v/%d/%x/%v", bt, bn, bv, be, nt, nn, nv, ne)
		}
		if be, ne := ValidateBERElement(wire, base...), ValidateBERElement(wire, nested...); !sameOptionError(be, ne) {
			t.Fatalf("path changed structural validation: %v / %v", be, ne)
		}
	})
}

func sameOptionError(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Error() == b.Error()
}
