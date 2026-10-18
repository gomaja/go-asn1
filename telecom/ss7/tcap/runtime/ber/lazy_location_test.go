// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/lazy_location_test.go; SHA-256 b494bd3e4e6c1bc1d243e56448182ea28f0ae2b3ea9bb21f837ea2ef9900ebf1.
package ber

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func TestGeneratedMarkersDeferDiagnosticPaths(t *testing.T) {
	wire := []byte{0x30, 6, 2, 1, 1, 4, 1, 'A'}
	options := TrackTCAPForm(nil, "Invoke")
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
	options := TrackTCAPForm(nil, "Invoke")
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
	options := TrackTCAPForm(nil, "Invoke")
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

func TestNestedProfileSourceAllocationBound(t *testing.T) {
	options := TrackTCAPForm(nil, "TCMessage", "TCAPMessages", "TCMessage")
	data, err := OwnGeneratedBERInput([]byte{0x30, 3, 2, 1, 1}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(100, func() {
		nested := TrackTCAPForm(options, "Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke")
		config, err := decodeOptions(nested)
		if err != nil || !config.profileNested || config.profileType != "Invoke" {
			panic("nested profile policy lost")
		}
	})
	if allocations > 2 {
		t.Fatalf("nested profile source allocated %.0f times, want at most two", allocations)
	}
}

// The wire parser bounds elements before these markers are retained. Retained
// locations and the first diagnostic must also scale with the element count.
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

func TestLocatedDialogueRetainsCompactContextAndReceivedOffset(t *testing.T) {
	wire, _ := hex.DecodeString("6b152813060700118605010101a0086006a10406022a03")
	inner, _ := hex.DecodeString("6006a10406022a03")
	options := TrackTCAPForm(nil, "DialoguePortion", "TCAPMessages")
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err = PrepareGeneratedBERInput(data, options)
	if err != nil {
		t.Fatal(err)
	}
	options = LocateDecodedElement(data, "DialoguePortion", options)
	located := LocateDialogueContent(data, inner, options)
	if len(located) != 1 {
		t.Fatalf("located dialogue lost compact context: %d options", len(located))
	}
	config, err := decodeOptions(located)
	if err != nil {
		t.Fatal(err)
	}
	if config.location == options[0].(*generatedDecodeOption).config.location {
		t.Fatal("dialogue changed its caller's location")
	}
	child := LocateDecodedElement(inner, "DialoguePDU", ChildDecodeOptions(located, "dialoguePDU"))
	err = CheckDecodedValue(child, "", "test constraint", "bad")
	var violation *ValidationError
	if !errors.As(err, &violation) || violation.Offset == nil || *violation.Offset != 15 || violation.Path != "dialoguePDU" || fmt.Sprint(violation.ChildIndexes) != "[0 1 0]" {
		t.Fatalf("copied dialogue location: %v", err)
	}
	if options[0].(*generatedDecodeOption).config.location.receivedOffset() != 0 {
		t.Fatal("dialogue changed the parent offset")
	}
}
