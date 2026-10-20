// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_context_test.go; SHA-256 afc8dfecdfc5f49eef0b4ebce7c7e621d8ac23654cec504fdb7e8e7fab83acb6.
package ber

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestGeneratedDecodeContextBindsExactValidatedElements(t *testing.T) {
	input := []byte{0x30, 0x06, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	copied, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(copied, options...); err != nil {
		t.Fatal(err)
	}
	owned, contextOptions, err := PrepareGeneratedBERInput(copied, options)
	if err != nil {
		t.Fatal(err)
	}
	input[4] = 0x43
	if !bytes.Equal(owned, []byte{0x30, 0x06, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42}) {
		t.Fatalf("owned input changed with caller's buffer: %x", owned)
	}
	child := ChildDecodeOptions(contextOptions, "field")
	if err := ValidateBERElement(owned[2:5], child...); err != nil {
		t.Fatalf("validated child rejected: %v", err)
	}
	if err := ValidateBERElement(owned[3:5], child...); err == nil {
		t.Fatal("interior primitive bytes accepted as a validated element")
	}
	if err := ValidateBERElement(owned[2:4], child...); err == nil {
		t.Fatal("truncated child accepted as a validated element")
	}
	if err := ValidateBERElement(owned[5:8], child...); err != nil {
		t.Fatalf("second validated child rejected: %v", err)
	}
	if err := ValidateBERElement(owned[2:5], ChildDecodeContext(contextOptions, "bad.path")); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid context path = %v", err)
	}
	indexOption := ChildDecodeIndexContext(contextOptions, 7)
	if err := CheckDecodedLength([]DecodeOption{indexOption}, "field", "SIZE (2)", 1); err == nil || err.(*ValidationError).Path != "element[7].field" {
		t.Fatalf("indexed path = %v", err)
	}
	primitiveWithTLV := []byte{0x30, 0x04, 0x04, 0x02, 0x05, 0x00}
	otherOptions := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	otherCopied, err := OwnGeneratedBERInput(primitiveWithTLV, otherOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(otherCopied, otherOptions...); err != nil {
		t.Fatal(err)
	}
	otherOwned, otherContext, err := PrepareGeneratedBERInput(otherCopied, otherOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(otherOwned[4:6], ChildDecodeOptions(otherContext, "field")...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("valid TLV inside primitive contents = %v", err)
	}
}

func TestGeneratedDecodeContextValidatesItsOwnedInput(t *testing.T) {
	input := []byte{0x30, 0x03, 0x04, 0x01, 'A'}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	input[4] = 'B'
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	prepared, contextOptions, err := PrepareGeneratedBERInput(owned, options)
	if err != nil || !bytes.Equal(prepared, []byte{0x30, 0x03, 0x04, 0x01, 'A'}) {
		t.Fatalf("prepared input = %x, %v", prepared, err)
	}
	if &prepared[0] != &owned[0] {
		t.Fatal("preparation copied the already validated buffer")
	}
	source := contextOptions[0].(*generatedDecodeOption).source
	if !bytes.Equal(source.validated, prepared) || &source.validated[0] == &prepared[0] {
		t.Fatal("validation proof does not own a private copy")
	}
	if err := ValidateBERElement(prepared[2:], ChildDecodeContext(contextOptions, "data")); err != nil {
		t.Fatalf("child lost its validated span: %v", err)
	}
}

func TestGeneratedDecodeContextRevalidatesChangedValidContents(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput([]byte{0x30, 0x03, 0x04, 0x01, 'A'}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	owned[4] = 'B'
	prepared, context, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prepared, []byte{0x30, 0x03, 0x04, 0x01, 'B'}) {
		t.Fatalf("prepared input = %x", prepared)
	}
	if err := ValidateBERElement(prepared[2:], ChildDecodeContext(context, "data")); err != nil {
		t.Fatalf("revalidated child = %v", err)
	}
	if !bytes.Equal(context[0].(*generatedDecodeOption).source.validated, prepared) {
		t.Fatal("new proof does not cover changed contents")
	}
}

func TestGeneratedDecodeContextSpanBoundaries(t *testing.T) {
	for _, size := range []int{65535, 65536} {
		child, err := EncodeOctetString(bytes.Repeat([]byte{'A'}, size-8))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := EncodeSequence(child)
		if err != nil || len(wire) != size {
			t.Fatalf("size %d: encoded length %d, %v", size, len(wire), err)
		}
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
		_, _, contents, err := DecodeTLV(owned, options...)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(contents, ChildDecodeContext(options, "data")); err != nil {
			t.Fatalf("size %d: validated child rejected: %v", size, err)
		}
	}
}

func TestGeneratedDecodeContextRejectsOversizedInputBeforeCopy(t *testing.T) {
	input := []byte{0x30, 0x03, 0x04, 0x01, 'A'}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting(), WithDecodeLimits(DecodeLimits{MaxWork: 4})})
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil || &owned[0] != &input[0] {
		t.Fatalf("oversized input copied: %v", err)
	}
	if err := ValidateBERElement(owned, options...); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized input = %v, want resource limit", err)
	}
}

func TestGeneratedDecodeContextChecksReconstructedUniversalTag(t *testing.T) {
	original := []byte{0x80, 0x02, 0x00, 0x00}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput(original, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	_, contextOptions, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed := []byte{0x01, 0x02, 0x00, 0x00}
	if err := ValidateBERElement(reconstructed, contextOptions...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("reconstructed BOOLEAN = %v, want invalid contents", err)
	}
	if err := ValidateBERElement(reconstructed, options...); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("original entry = %v, want invalid contents", err)
	}
}

func TestGeneratedDecodeContextKeepsReceivedOctetsSeparateFromValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		wire   []byte
		decode func([]byte, []DecodeOption) ([]byte, error)
	}{
		{name: "implicit octet string", wire: []byte{0x80, 0x02, 'A', 'B'}, decode: func(value []byte, options []DecodeOption) ([]byte, error) {
			return DecodeImplicitOctetStringValue(false, value, options...)
		}},
		{name: "implicit bit string", wire: []byte{0x80, 0x02, 0, 0x80}, decode: func(value []byte, options []DecodeOption) ([]byte, error) {
			decoded, _, err := DecodeImplicitBitStringValue(false, value, options...)
			return decoded, err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
			owned, err := OwnGeneratedBERInput(test.wire, options)
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
			_, _, contents, err := DecodeTLV(owned, options...)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := test.decode(contents, options)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(owned)
			decoded[0] ^= 0xff
			if !bytes.Equal(owned, original) {
				t.Fatalf("decoded value changed retained BER: %x, want %x", owned, original)
			}
		})
	}
}

func TestGeneratedDecodeContextUsesRecordedIndefiniteBoundaries(t *testing.T) {
	wire := []byte{0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	copied, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(copied, options...); err != nil {
		t.Fatal(err)
	}
	owned, contextOptions, err := PrepareGeneratedBERInput(copied, options)
	if err != nil {
		t.Fatal(err)
	}
	_, total, outerContents, err := DecodeTLV(owned, contextOptions...)
	if err != nil || total != len(owned) {
		t.Fatalf("outer = %d, %v", total, err)
	}
	_, total, innerContents, err := DecodeTLV(outerContents, contextOptions...)
	if err != nil || total != len(outerContents) {
		t.Fatalf("inner = %d, %v", total, err)
	}
	_, total, _, err = DecodeTLV(innerContents, contextOptions...)
	if err != nil || total != len(innerContents) {
		t.Fatalf("leaf = %d, %v", total, err)
	}
}

func TestGeneratedDecodeContextRechecksIndefiniteTree(t *testing.T) {
	wire := nestedIndefiniteBER(4)
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	prepared, contextOptions, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	// Rechecking uses the current limits even after the earlier scan proved
	// this buffer valid. A recorded boundary cannot bypass a later limit.
	contextOptions[0].(*generatedDecodeOption).config.limits.MaxDepth = 1
	_, total, _, err := DecodeTLV(prepared, contextOptions...)
	if !errors.Is(err, ErrResourceLimit) || total != 0 {
		t.Fatalf("nested root = %d/%d, %v; want resource limit", total, len(prepared), err)
	}
}

func TestGeneratedDecodeContextRequiresCompletedValidation(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	if _, _, err := PrepareGeneratedBERInput([]byte{0x05, 0x00}, options); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("unvalidated input = %v", err)
	}
	if err := ValidateBERElement([]byte{0x05, 0x00}, options...); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareGeneratedBERInput([]byte{0x05, 0x00}, options); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("input not owned by the context = %v", err)
	}
	var zero generatedDecodeOption
	if err := ValidateBERElement([]byte{0x05, 0x00}, &zero); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("zero context = %v", err)
	}
	if _, err := OwnGeneratedBERInput([]byte{0x05, 0x00}, []DecodeOption{&zero}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("zero context ownership = %v", err)
	}
}

func TestGeneratedAdaptiveProofOwnsWorkingInput(t *testing.T) {
	deep := []byte{0x05, 0x00}
	for range 10 {
		deep = append([]byte{0x30, byte(len(deep))}, deep...)
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{"root indefinite", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}},
		{"nested indefinite", []byte{0x30, 0x06, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00}},
		{"deep definite", deep},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := bytes.Clone(test.wire)
			options := TrackBERForm(nil)
			owned, err := OwnGeneratedBERInput(input, options)
			if err != nil {
				t.Fatal(err)
			}
			prepared, context, err := PrepareGeneratedBERInput(owned, options)
			if err != nil {
				t.Fatal(err)
			}
			if len(context) != 1 || !isGeneratedDecodeContext(context[0]) {
				t.Fatal("adaptive mode did not engage the proof")
			}
			if sameBERSlice(input, prepared) {
				t.Fatal("proof retained the caller's mutable input")
			}
			input[len(input)-1] ^= 1
			if !bytes.Equal(prepared, test.wire) {
				t.Fatal("caller mutation changed the prepared input")
			}
		})
	}
}

func TestGeneratedProofRequiresFormTracker(t *testing.T) {
	_, err := OwnGeneratedBERInput([]byte{0x05, 0x00}, []DecodeOption{ForceGeneratedBERProofForTesting()})
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("proof without form tracker = %v, want invalid value", err)
	}
}

func TestGeneratedProofEmptyInputReportsWireError(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = PrepareGeneratedBERInput(owned, options)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty proof input = %v, want truncated wire error", err)
	}
}

func TestGeneratedLightReplayDoesNotClaimReconstructedWireTag(t *testing.T) {
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput([]byte{0x80, 0x01, 0x00}, options)
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	node := CaptureGeneratedBERReplay([]byte{0x01, 0x01, 0x00}, options)
	if node == nil || node.wireTagKnown {
		t.Fatalf("reconstructed IMPLICIT tag claimed to be received: %+v", node)
	}
}

func TestGeneratedLightChildPreflightMarkerAvoidsAllocations(t *testing.T) {
	options := TrackBERForm(nil)
	child := []DecodeOption{ChildDecodeContext(options, "field")}
	wire := []byte{0x05, 0x00}
	allocs := testing.AllocsPerRun(1000, func() {
		MarkPreflightTarget(child, "leaf", wire)
	})
	if allocs != 0 {
		t.Fatalf("successful child preflight marker allocated %.0f times", allocs)
	}
}

func TestGeneratedLightChildStagingAvoidsAllocations(t *testing.T) {
	options := []DecodeOption{ChildDecodeContext(TrackBERForm(nil), "field")}
	allocs := testing.AllocsPerRun(1000, func() {
		staged, commit := StageDecodeReports(options)
		_ = TrackBERForm(staged)
		commit(true)
	})
	if allocs != 0 {
		t.Fatalf("successful child report and form staging allocated %.0f times", allocs)
	}
}

func TestGeneratedLightChildOptionUsesOneAllocation(t *testing.T) {
	options := TrackBERForm(nil)
	allocs := testing.AllocsPerRun(1000, func() {
		_ = ChildDecodeContext(options, "field")
	})
	if allocs > 1 {
		t.Fatalf("light child option allocated %.0f times, want at most one", allocs)
	}
}

func TestGeneratedLightChildKeepsNestedConstraintPaths(t *testing.T) {
	root := TrackBERForm(nil)
	outer := []DecodeOption{ChildDecodeContext(root, "outer")}
	inner := []DecodeOption{ChildDecodeContext(outer, "inner")}
	var constraint *ValidationError
	if err := CheckDecodedLength(inner, "leaf", "SIZE (2)", 1); !errors.As(err, &constraint) || constraint.Path != "outer.inner.leaf" {
		t.Fatalf("nested light constraint path = %v", err)
	}
	collection := []DecodeOption{ParentCollectionSizeDecodeContext(inner, "items")}
	if err := CheckDecodedCollectionLength(collection, "items", "SIZE (2)", 1); err != nil {
		t.Fatalf("parent checked collection size again: %v", err)
	}
}

func TestGeneratedProofChildOptionSliceUsesOneAllocation(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput([]byte{0x30, 0x02, 0x05, 0x00}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	_, context, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_ = ChildDecodeOptions(context, "child")
	})
	if allocs > 1 {
		t.Fatalf("proof child option allocated %.0f times, want at most one", allocs)
	}
}

func TestGeneratedAdaptiveLightUsesOneWorkingCopy(t *testing.T) {
	input := []byte{0x04, 0x81, 0x01, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	if sameBERSlice(input, owned) {
		t.Fatal("light input still aliases the caller")
	}
	prepared, result, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBERSlice(owned, prepared) || len(result) != len(options) {
		t.Fatal("shallow definite input did not use light mode")
	}
	config, err := decodeOptions(result)
	if err != nil {
		t.Fatal(err)
	}
	if config.form.validated != nil || config.form.owned != nil || !sameBERSlice(config.form.lightOwned, prepared) || !sameBERSlice(config.form.lightInput, prepared) {
		t.Fatal("light mode did not retain exactly its working input")
	}
	node := CaptureGeneratedBERReplay(prepared, result)
	if node == nil || !sameBERSlice(node.original, prepared) || !sameBERSlice(config.form.lightOwned, node.original) {
		t.Fatal("light replay did not reuse the one working copy")
	}
	input[1] = 0x02
	if !bytes.Equal(node.original, []byte{0x04, 0x81, 0x01, 'A'}) {
		t.Fatal("caller mutation changed captured received octets")
	}
}

func TestGeneratedAdaptiveCanonicalLightUsesOneWorkingCopy(t *testing.T) {
	input := []byte{0x04, 0x01, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	prepared, result, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	if sameBERSlice(input, owned) || !sameBERSlice(owned, prepared) || len(result) != len(options) {
		t.Fatal("canonical light decode did not use one working copy")
	}
	config, err := decodeOptions(result)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBERSlice(config.form.lightOwned, owned) || config.form.validated != nil {
		t.Fatal("canonical light decode did not retain its working input")
	}
}

func TestGeneratedLightReplayRetainsValueBeforeCallerMutation(t *testing.T) {
	type value struct {
		contents byte
		node     *ReplayNode
	}
	input := []byte{0x04, 0x81, 0x01, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &value{contents: 'A', node: CaptureGeneratedBERReplay(data, options)}
	encodes := 0
	encode := func(v *value, options ...EncodeOption) ([]byte, error) {
		encodes++
		if _, err := PrepareBERReplay(v.node, options, nil, v); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{0x04, 0x01, v.contents}, v.node, options), nil
	}
	if err := CompleteGeneratedBERDecode(options, decoded, encode); err != nil {
		t.Fatal(err)
	}
	if encodes != 1 {
		t.Fatalf("light decode encoded baseline %d times, want one", encodes)
	}
	input[3] = 'X'
	prepared, err := PrepareBERReplay(decoded.node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode(decoded, mode)
	}, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if replay, ok := PreparedBERReplay(decoded.node, prepared); !ok || !bytes.Equal(replay, []byte{0x04, 0x81, 0x01, 'A'}) {
		t.Fatalf("unchanged replay = %x, enabled %t", replay, ok)
	}
	decoded.contents = 'B'
	prepared, err = PrepareBERReplay(decoded.node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode(decoded, mode)
	}, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if replay, ok := PreparedBERReplay(decoded.node, prepared); !ok || !bytes.Equal(replay, []byte{0x04, 0x01, 'B'}) {
		t.Fatalf("changed replay = %x, enabled %t", replay, ok)
	}
}

func TestGeneratedLightReplayBaselineFailureDoesNotRejectDecode(t *testing.T) {
	type value struct {
		contents byte
		node     *ReplayNode
	}
	input := []byte{0x04, 0x81, 0x01, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &value{contents: 'A', node: CaptureGeneratedBERReplay(data, options)}
	if err := CompleteGeneratedBERDecode(options, decoded, func(*value, ...EncodeOption) ([]byte, error) {
		return nil, errors.New("baseline unavailable")
	}); err != nil {
		t.Fatalf("valid decode rejected by replay baseline: %v", err)
	}
	if !decoded.node.state.disabled {
		t.Fatal("replay remains enabled after a failed baseline")
	}
	prepared, err := PrepareBERReplay(decoded.node, nil, nil, decoded)
	if err != nil || len(prepared) != 0 {
		t.Fatalf("fresh encode preparation after failed baseline: options=%d error=%v", len(prepared), err)
	}
}

func TestGeneratedAdaptiveNestedIndefiniteToleranceMatchesForcedModes(t *testing.T) {
	// The malformed UTF8String is reported in tolerant mode. Its indefinite
	// wrapper is nested, so adaptive preparation scans it a second time.
	wire := []byte{0x30, 0x07, 0x2c, 0x80, 0x04, 0x01, 0xc3, 0x00, 0x00}
	var baseline []byte
	for _, test := range []struct {
		name string
		mode DecodeOption
	}{
		{"light", ForceGeneratedBERLightForTesting()},
		{"proof", ForceGeneratedBERProofForTesting()},
		{"adaptive", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var reports ViolationLog
			options := []DecodeOption{WithTolerance(&reports)}
			if test.mode != nil {
				options = append(options, test.mode)
			}
			options = TrackBERForm(options)
			owned, err := OwnGeneratedBERInput(bytes.Clone(wire), options)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = PrepareGeneratedBERInput(owned, options)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(reports.Snapshot())
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "light" {
				baseline = got
			} else if !bytes.Equal(got, baseline) {
				t.Fatalf("tolerance reports differ: %s vs %s", got, baseline)
			}
		})
	}
}

func nestedIndefiniteBER(depth int) []byte {
	wire := make([]byte, 0, depth*4+2)
	for range depth {
		wire = append(wire, 0x30, 0x80)
	}
	wire = append(wire, 0x05, 0x00)
	for range depth {
		wire = append(wire, 0x00, 0x00)
	}
	return wire
}

func decodeNestedGeneratedContext(wire []byte, depth int) error {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		return err
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		return err
	}
	current, contextOptions, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		return err
	}
	for range depth {
		_, total, contents, err := DecodeTLV(current, contextOptions...)
		if err != nil || total != len(current) {
			return fmt.Errorf("nested BER element: consumed %d/%d: %w", total, len(current), err)
		}
		current = contents
	}
	_, total, _, err := DecodeTLV(current, contextOptions...)
	if err != nil || total != len(current) {
		return fmt.Errorf("nested BER leaf: consumed %d/%d: %w", total, len(current), err)
	}
	return nil
}

func TestGeneratedDecodeContextDepthAllocationsAreLinear(t *testing.T) {
	measure := func(depth int) float64 {
		wire := nestedIndefiniteBER(depth)
		return testing.AllocsPerRun(3, func() {
			if err := decodeNestedGeneratedContext(wire, depth); err != nil {
				t.Fatal(err)
			}
		})
	}
	small, large := measure(10), measure(100)
	if large > small*15 {
		t.Fatalf("depth allocations: 10 levels %.0f, 100 levels %.0f", small, large)
	}
}

func TestGeneratedContextOptionResolutionDoesNotAllocate(t *testing.T) {
	options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting()})
	owned, err := OwnGeneratedBERInput([]byte{0x05, 0x00}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBERElement(owned, options...); err != nil {
		t.Fatal(err)
	}
	_, contextOptions, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	allocated := testing.AllocsPerRun(100, func() {
		if _, err := decodeOptions(contextOptions); err != nil {
			t.Fatal(err)
		}
	})
	if allocated != 0 {
		t.Fatalf("generated context option resolution allocated %.0f objects", allocated)
	}
}

func BenchmarkGeneratedDecodeContextDepth(b *testing.B) {
	for _, depth := range []int{10, 20, 40, 80, 120} {
		b.Run(fmt.Sprintf("Depth%d", depth), func(b *testing.B) {
			wire := nestedIndefiniteBER(depth)
			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()
			for range b.N {
				if err := decodeNestedGeneratedContext(wire, depth); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzGeneratedBERContext(f *testing.F) {
	f.Add([]byte{0x05, 0x00})
	f.Add(nestedIndefiniteBER(4))
	f.Add([]byte{0x30, 0x04, 0x04, 0x02, 0x05, 0x00})
	f.Add([]byte{0x30, 0x80, 0x00})
	f.Fuzz(func(t *testing.T, wire []byte) {
		options := TrackBERForm([]DecodeOption{ForceGeneratedBERProofForTesting(), WithDecodeLimits(DecodeLimits{MaxDepth: 32, MaxElements: 128, MaxWork: 4096})})
		owned, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBERElement(owned, options...); err != nil {
			return
		}
		prepared, contextOptions, err := PrepareGeneratedBERInput(owned, options)
		if err != nil {
			t.Fatal(err)
		}
		_, total, _, err := DecodeTLV(prepared, contextOptions...)
		if err != nil || total != len(prepared) {
			t.Fatalf("validated element decoded %d/%d bytes: %v", total, len(prepared), err)
		}
	})
}

// Exported fields exercise the typed baseline comparison used by generated values.
func TestGeneratedTypedReplaySnapshotsRootBeforeMutation(t *testing.T) {
	type value struct {
		Contents byte
		node     *ReplayNode
	}
	input := []byte{0x04, 0x81, 0x01, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &value{Contents: 'A', node: CaptureGeneratedBERReplay(data, options)}
	encodes := 0
	encode := func(v *value, options ...EncodeOption) ([]byte, error) {
		encodes++
		if _, err := PrepareBERReplay(v.node, options, nil, v); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{0x04, 0x01, v.Contents}, v.node, options), nil
	}
	compare := func(a, b *value, _ *BERReplayComparisons) int {
		if a.Contents == b.Contents {
			return int(berValueEqual)
		}
		return int(berValueDifferent)
	}
	if err := CompleteGeneratedBERDecode(options, decoded, encode, compare); err != nil {
		t.Fatal(err)
	}
	if encodes != 0 {
		t.Fatalf("typed decode encoded baseline %d times, want none", encodes)
	}
	input[3] = 'X'
	prepared, err := PrepareBERReplay(decoded.node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode(decoded, mode)
	}, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if replay, ok := PreparedBERReplay(decoded.node, prepared); !ok || !bytes.Equal(replay, []byte{0x04, 0x81, 0x01, 'A'}) {
		t.Fatalf("unchanged replay = %x, enabled %t", replay, ok)
	}
	decoded.Contents = 'B'
	prepared, err = PrepareBERReplay(decoded.node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode(decoded, mode)
	}, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if replay, ok := PreparedBERReplay(decoded.node, prepared); ok && !bytes.Equal(replay, []byte{0x04, 0x01, 'B'}) {
		t.Fatalf("changed replay = %x, enabled %t", replay, ok)
	}
	encoded, err := encode(decoded, prepared...)
	if err != nil || !bytes.Equal(encoded, []byte{0x04, 0x01, 'B'}) {
		t.Fatalf("edited encode=%x: %v", encoded, err)
	}
}
