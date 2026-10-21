// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/lazy_location_test.go; SHA-256 e63dfc686c4ed3a9b4a2eca42fcf907a0889181e4ad091241ec9d5a86c1f326f.
package ber

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

func TestGeneratedMarkersDeferDiagnosticPaths(t *testing.T) {
	wire := []byte{0x30, 6, 2, 1, 1, 4, 1, 'A'}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Invoke", options)
	child := ChildDecodeOptions(options, "argument")
	MarkPreflightTarget(child, "value", data[5:])
	context := child[0].(*generatedDecodeOption)
	if context.pathSet {
		t.Fatal("successful field marker materialized its diagnostic path")
	}
	err = CheckDecodedValue(child, "value", "test constraint", "bad")
	var violation *ValidationError
	if !errors.As(err, &violation) || violation.Path != "argument.value" || violation.Offset == nil || *violation.Offset != 5 || len(violation.ChildIndexes) != 1 || violation.ChildIndexes[0] != 1 {
		t.Fatalf("deferred marker location: %+v", err)
	}
}

func TestGeneratedLocationResolvesOnlyOnFailure(t *testing.T) {
	wire := []byte{0x30, 3, 2, 1, 1}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Invoke", options)
	child := LocateDecodedElement(data[2:], "InvokeId", ChildDecodeOptions(options, "invokeId"))
	context := child[0].(*generatedDecodeOption)
	if context.config.location.offset >= 0 {
		t.Fatal("successful child resolved its fallback offset")
	}
	err = CheckDecodedValue(child, "", "test constraint", "bad")
	var violation *ValidationError
	if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != 2 || len(violation.ChildIndexes) != 1 || violation.ChildIndexes[0] != 0 || violation.Path != "invokeId" || violation.Source != "InvokeId" {
		t.Fatalf("deferred child location: %+v", err)
	}
	located := LocateDecodeError(ErrInvalidValue, child)
	var element *ElementError
	if !errors.As(located, &element) || element.Offset() != 2 || len(element.ChildIndexes()) != 1 || element.ChildIndexes()[0] != 0 {
		t.Fatalf("typed error location: %v", located)
	}
}

func TestDeferredMarkersPreserveLastReceivedField(t *testing.T) {
	wire := []byte{0x30, 6, 2, 1, 1, 2, 1, 2}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Invoke", options)
	MarkPreflightTarget(options, "invokeId", data[2:])
	MarkPreflightTarget(options, "opcode", data[5:])
	child := LocateDecodedElement([]byte{0x30, 3, 2, 1, 2}, "Code", ChildDecodeOptions(options, "opcode"))
	location := child[0].(*generatedDecodeOption).config.location
	if got := location.receivedOffset(); got != 5 {
		t.Fatalf("reconstructed offset=%d want 5", got)
	}
	if options[0].(*generatedDecodeOption).pathSet {
		t.Fatal("reconstructed child formatted its parent path")
	}
	err = CheckDecodedValue(child, "", "test constraint", "bad")
	var v *ValidationError
	if !errors.As(err, &v) || v.Offset == nil || *v.Offset != 5 || len(v.ChildIndexes) != 1 || v.ChildIndexes[0] != 1 {
		t.Fatalf("reconstructed identifier location: %+v", err)
	}
}

func TestDeferredMarkerStorageGrowthBound(t *testing.T) {
	for _, count := range []int{16, 1024, 8192} {
		body := make([]byte, 0, 3*count)
		for range count {
			body = append(body, 2, 1, 1)
		}
		wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}, body)
		if err != nil {
			t.Fatal(err)
		}
		options := TrackBERForm(nil)
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(data, "Invoke", options)
		header := len(data) - len(body)
		var child []DecodeOption
		for index := range count {
			child = ChildDecodeIndexOptions(options, index)
			MarkPreflightTarget(child, "value", data[header+index*3:])
		}
		config, err := decodeOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		origin := config.location.origin
		if origin.marks != nil || len(origin.pendingMarks) != count || cap(origin.pendingMarks) > 2*count+8 {
			t.Fatalf("%d elements: eager paths or unbounded storage (%d/%d)", count, len(origin.pendingMarks), cap(origin.pendingMarks))
		}
		err = CheckDecodedValue(child, "value", "test constraint", "bad")
		var violation *ValidationError
		if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != header+(count-1)*3 || violation.Path != fmt.Sprintf("element[%d].value", count-1) {
			t.Fatalf("%d elements: last marker location: %v", count, err)
		}
		if origin.ancestryVisits > count+1 {
			t.Fatalf("%d elements: ancestry made %d visits", count, origin.ancestryVisits)
		}
	}
}

func TestPrimitiveElementMarksDeferNames(t *testing.T) {
	wire := []byte{0x30, 0x09, 0x04, 3, 0x11, 0x22, 0x33, 0x04, 2, 0xaa, 0xbb}
	options := TrackBERForm(nil)
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "Module.HLR-List", options)
	MarkPreflightElement(options, 0, data[2:])
	MarkPreflightElement(options, 1, data[7:])
	config, err := decodeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	var marks []decodedElementMark
	if config.location.origin != nil {
		marks = config.location.origin.pendingMarks
	}
	if len(marks) != 0 || config.location.elementIndex != 1 || &config.location.elementRaw[0] != &data[7] || config.location.field != "" {
		t.Fatalf("eager element marks or missing index: %+v, location=%+v", marks, config.location)
	}
	err = CheckDecodedLength(options, "element[1]", "SIZE (3..8)", 2)
	var violation *ValidationError
	if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != 7 || violation.Path != "element[1]" || len(violation.ChildIndexes) != 1 || violation.ChildIndexes[0] != 1 {
		t.Fatalf("deferred element location: %v", err)
	}
}

func TestPrimitiveElementLocationStorageIsConstant(t *testing.T) {
	for _, count := range []int{16, 1024, 8192} {
		body := make([]byte, 0, count*3)
		for range count {
			body = append(body, 4, 1, 'A')
		}
		wire, err := EncodeTLV(tag.Tag{Number: tag.TagSequence, Constructed: true}, body)
		if err != nil {
			t.Fatal(err)
		}
		options := TrackBERForm(nil)
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(data, "Module.List", options)
		header := len(data) - len(body)
		for index := range count {
			MarkPreflightElement(options, index, data[header+3*index:])
		}
		config, err := decodeOptions(options)
		if err != nil {
			t.Fatal(err)
		}
		if config.location.origin != nil && (len(config.location.origin.pendingMarks) != 0 || config.location.origin.marks != nil) || config.location.elementIndex != count-1 {
			t.Fatalf("%d elements retained per-element locations", count)
		}
		err = CheckDecodedLength(options, fmt.Sprintf("element[%d]", count-1), "SIZE (2)", 1)
		var violation *ValidationError
		if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != header+3*(count-1) || len(violation.ChildIndexes) != 1 || violation.ChildIndexes[0] != count-1 {
			t.Fatalf("%d elements: %v", count, err)
		}
		if config.location.origin.ancestryVisits > count+1 {
			t.Fatalf("%d elements: %d ancestry visits", count, config.location.origin.ancestryVisits)
		}
	}
}
