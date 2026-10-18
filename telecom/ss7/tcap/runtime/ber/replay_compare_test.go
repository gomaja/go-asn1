// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_compare_test.go; SHA-256 f7b6095c0b34e63b42a07801f68b80ab303b4c14e4e5fb190f63c51754fc9106.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"math/big"
	"reflect"
	"testing"
)

func TestReplayPrimitiveComparatorMatchesReference(t *testing.T) {
	values := []any{
		big.NewInt(-129), big.NewInt(0), big.NewInt(127),
		&runtime.RawValue{},
		&runtime.RawValue{Bytes: []byte{4, 1, 'A'}},
		&runtime.RawValue{Class: 2, Tag: 1, Bytes: []byte{0x81, 1, 'A'}},
		&runtime.RawValue{Bytes: []byte{4, 1, 'B'}},
		&runtime.BitString{Bytes: []byte{0x80}, BitLength: 1},
		&runtime.BitString{Bytes: []byte{0x81}, BitLength: 1},
		&runtime.BitString{Bytes: []byte{0}, BitLength: 1},
		&runtime.BitString{Bytes: []byte{0}, BitLength: 9},
		&runtime.ObjectIdentifier{},
		new(runtime.MustObjectIdentifier("1.2.3")),
	}
	for _, encoding := range []runtime.ExternalEncoding{0, runtime.ExternalSingleASN1Type, runtime.ExternalOctetAligned, runtime.ExternalArbitrary} {
		for _, payload := range [][]byte{nil, {4, 1, 'A'}, {4, 1, 'B'}} {
			for _, descriptor := range []*string{nil, new("a"), new("b")} {
				values = append(values, &runtime.External{Encoding: encoding, SingleASN1Type: runtime.RawValue{Bytes: payload}, OctetAligned: payload, DataValueDescriptor: descriptor})
			}
		}
	}
	for _, a := range values {
		for _, b := range values {
			if reflect.TypeOf(a) != reflect.TypeOf(b) {
				continue
			}
			for _, accessible := range []bool{true, false} {
				left, right := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
				if !accessible {
					// A private field retains the exact type while making Interface
					// and pointer projection unavailable to the reference.
					left = reflect.ValueOf(struct{ value any }{a}).Field(0).Elem().Elem()
					right = reflect.ValueOf(struct{ value any }{b}).Field(0).Elem().Elem()
				}
				got := berValueComparison(CompareBERReplayPrimitive(a, b, accessible))
				want := compareBERValueNodes(left, right, 0, nil)
				if got != want {
					t.Fatalf("%T accessible=%t: generated %d reference %d", a, accessible, got, want)
				}
			}
		}
	}
}

func TestGeneratedTypedLightReplayDefersComparisonStream(t *testing.T) {
	type value struct {
		Data []byte
		Node *ReplayNode
	}
	input := []byte{4, 0x81, 1, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &value{Data: data[len(data)-1:], Node: CaptureGeneratedBERReplay(data, options)}
	encodes := 0
	encode := func(v *value, options ...EncodeOption) ([]byte, error) {
		encodes++
		if _, err := PrepareBERReplay(v.Node, options, nil, v); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(append([]byte{4, 1}, v.Data...), v.Node, options), nil
	}
	compare := func(a, b *value, nodes *BERReplayComparisons) int {
		result := int(berComparison(bytes.Equal(a.Data, b.Data)))
		nodes.Record(a.Node, b.Node, result)
		return result
	}
	if err := CompleteGeneratedBERDecode(options, decoded, encode, compare); err != nil {
		t.Fatal(err)
	}
	if encodes != 0 {
		t.Fatalf("typed light decode encoded comparison stream %d times, want zero", encodes)
	}
	input[len(input)-1] = 'X'
	prepared, err := PrepareBERReplay(decoded.Node, nil, nil, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := PreparedBERReplay(decoded.Node, prepared); !ok || !bytes.Equal(got, []byte{4, 0x81, 1, 'A'}) {
		t.Fatalf("received form = %x, enabled %t", got, ok)
	}
	decoded.Data[0] = 'B'
	if bytes.Equal(decoded.Node.original, []byte{4, 0x81, 1, 'B'}) {
		t.Fatal("editable bytes still alias received replay")
	}
}

func TestNestedDecodeLocationDoesNotAllocateAnotherOrigin(t *testing.T) {
	wire := []byte{0x30, 3, 4, 1, 'A'}
	options := LocateDecodedElement(wire, "root", nil)
	// A nested locator needs its location and the extended option slice. The
	// root ancestry scanner and its field map are shared by the entire decode.
	allocs := testing.AllocsPerRun(100, func() {
		child := LocateDecodedElement(wire[2:], "child", options)
		if len(child) == 0 {
			panic("missing child location")
		}
	})
	if allocs > 4 {
		t.Fatalf("nested location allocations=%.0f, want at most 4", allocs)
	}
}

func TestTCAPDecodeContextResolutionDoesNotAllocate(t *testing.T) {
	options := TrackTCAPForm(nil, "Begin", "TCAPMessages", "Begin")
	options = LocateDecodedElement([]byte{0x62, 3, 0x48, 1, 1}, "Begin", options)
	allocs := testing.AllocsPerRun(100, func() {
		config, err := decodeOptions(options)
		if err != nil || config.profileSource != "TCAPMessages.Begin" {
			panic("profile context lost")
		}
	})
	if allocs != 0 {
		t.Fatalf("resolved TCAP decode context allocations=%.0f, want zero", allocs)
	}
}

func TestForcedTCAPDecodeContextResolutionDoesNotAllocate(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		options := TrackTCAPForm([]DecodeOption{mode}, "Begin", "TCAPMessages", "Begin")
		allocs := testing.AllocsPerRun(100, func() {
			if _, err := decodeOptions(options); err != nil {
				panic(err)
			}
		})
		if allocs != 0 {
			t.Fatalf("forced TCAP decode context allocations=%.0f, want zero", allocs)
		}
	}
}

func TestTCAPEncodeContextResolutionDoesNotAllocate(t *testing.T) {
	options := []EncodeOption{tcapEncodeOption{}, encodeSourceOption("TCAPMessages.Begin")}
	allocs := testing.AllocsPerRun(100, func() {
		config, err := encodeOptions(options)
		if err != nil || !config.tcapEncoding || config.source != "TCAPMessages.Begin" {
			panic("profile context lost")
		}
	})
	if allocs != 0 {
		t.Fatalf("resolved TCAP encode context allocations=%.0f, want zero", allocs)
	}
}

func TestPreparedReplayRetainsTCAPEncodeBoundary(t *testing.T) {
	state := &ReplayState{nodeCount: 1}
	node := &ReplayNode{state: state, original: []byte{5, 0}}
	state.root = node
	state.same = func(any, *BERReplayComparisons) berValueComparison { return berValueDifferent }
	options, err := PrepareBERReplay(node, []EncodeOption{tcapEncodeOption{}, generatedEncodeMarker{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, option := range options {
		if _, ok := option.(generatedEncodeMarker); ok {
			found = true
		}
	}
	if !found {
		t.Fatal("replay lost generated encode boundary")
	}
	config, err := encodeOptions(options)
	if err != nil || !config.tcapEncoding {
		t.Fatalf("replay lost outer TCAP boundary: %v", err)
	}
}

func TestPreparedReplayReusesProvedUnchangedChild(t *testing.T) {
	state := new(ReplayState)
	root := &ReplayNode{state: state, original: []byte{0x30, 4, 4, 0x81, 1, 'A'}}
	child := &ReplayNode{state: state, original: root.original[2:]}
	var decisions BERReplayComparisons
	decisions.Record(child, child, int(berValueEqual))
	got, ok := PreparedBERReplay(child, []EncodeOption{replayModeOption{state: state, top: root, typed: &decisions}, generatedEncodeMarker{}})
	if !ok || !bytes.Equal(got, child.original) {
		t.Fatalf("known unchanged child was rebuilt: %x, enabled %t", got, ok)
	}
	decisions.Record(child, child, int(berValueUnknown))
	if _, ok := PreparedBERReplay(child, []EncodeOption{replayModeOption{state: state, top: root, typed: &decisions}}); ok {
		t.Fatal("unknown child bypassed stream comparison")
	}
}

func TestPreparedFastReplayReusesProvedUnchangedChild(t *testing.T) {
	state := new(ReplayState)
	root := &ReplayNode{state: state, original: []byte{0x30, 4, 4, 0x81, 1, 'A'}}
	child := &ReplayNode{state: state, original: root.original[2:]}
	var decisions BERReplayComparisons
	decisions.Record(child, child, int(berValueEqual))
	fast := &replayFastState{state: state, root: root, nodeValues: &decisions, matched: make(map[*ReplayNode]bool)}
	fast.enter(root)
	fast.enter(child)
	got, ok := PreparedBERReplay(child, []EncodeOption{replayModeOption{state: state, top: root, fast: fast, strict: true}})
	if !ok || !bytes.Equal(got, child.original) {
		t.Fatalf("fast known child was rebuilt: %x, enabled %t", got, ok)
	}
	if len(fast.stack) != 1 || !fast.stack[0].childReplayed || !fast.matched[child] || fast.uncertain {
		t.Fatal("fast shortcut lost parent placement bookkeeping")
	}
}

func TestPreparedReplayDoesNotSkipToleratedChild(t *testing.T) {
	for _, mode := range []string{"typed", "fast", "source-proof"} {
		t.Run(mode, func(t *testing.T) {
			state := &ReplayState{decodeTolerant: true}
			root := &ReplayNode{state: state, original: []byte{0x30, 3, 4, 0x81, 0}}
			child := &ReplayNode{state: state, original: root.original[2:]}
			var decisions BERReplayComparisons
			decisions.Record(child, child, int(berValueEqual))
			option := replayModeOption{state: state, top: root, typed: &decisions}
			var proof []func() bool
			if mode != "typed" {
				fast := &replayFastState{state: state, root: root, nodeValues: &decisions}
				fast.enter(root)
				fast.enter(child)
				option.typed, option.fast, option.strict = nil, fast, true
				if mode == "source-proof" {
					decisions.Record(child, child, int(berValueUnknown))
					proof = []func() bool{func() bool { return true }}
				}
			}
			if got, ok := PreparedBERReplay(child, []EncodeOption{option}, proof...); ok || got != nil {
				t.Fatalf("tolerated child bypassed its encoder: %x, enabled %t", got, ok)
			}
			if option.fast != nil && len(option.fast.stack) != 2 {
				t.Fatal("refused shortcut changed fast replay bookkeeping")
			}
		})
	}
}

func TestGeneratedUnknownReplayPreparesComparisonStreamAtDecode(t *testing.T) {
	type value struct {
		Data []byte
		Node *ReplayNode
	}
	input := []byte{4, 0x81, 1, 'A'}
	options := TrackBERForm(nil)
	owned, err := OwnGeneratedBERInput(input, options)
	if err != nil {
		t.Fatal(err)
	}
	data, options, err := PrepareGeneratedBERInput(owned, options)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &value{Data: data[len(data)-1:], Node: CaptureGeneratedBERReplay(data, options)}
	encodes := 0
	encode := func(v *value, opts ...EncodeOption) ([]byte, error) {
		encodes++
		if _, err := PrepareBERReplay(v.Node, opts, nil, v); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(append([]byte{4, 1}, v.Data...), v.Node, opts), nil
	}
	compare := func(*value, *value, *BERReplayComparisons) int { return int(berValueUnknown) }
	if err := CompleteGeneratedBERDecode(options, decoded, encode, compare); err != nil {
		t.Fatal(err)
	}
	if encodes != 1 || !decoded.Node.state.eagerBaseline {
		t.Fatalf("unknown decoded value has %d prepared comparison encodes, want one", encodes)
	}
	opts, err := PrepareBERReplay(decoded.Node, nil, func(mode EncodeOption) ([]byte, error) { return encode(decoded, mode) }, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if encodes != 2 {
		t.Fatalf("first replay used %d total comparison encodes, want two", encodes)
	}
	if got, ok := PreparedBERReplay(decoded.Node, opts); !ok || !bytes.Equal(got, input) {
		t.Fatalf("unknown received replay=%x enabled=%t", got, ok)
	}
}

func TestGeneratedLinearEncodeRequiresPrivateOptions(t *testing.T) {
	var log ViolationLog
	for _, test := range []struct {
		name string
		opts []EncodeOption
		want bool
	}{
		{"default", nil, true},
		{"private", []EncodeOption{generatedEncodeMarker{}, tcapEncodeOption{}, replayModeOption{state: new(ReplayState)}}, true},
		{"public-tolerance", []EncodeOption{generatedEncodeMarker{}, WithTolerance(&log)}, false},
		{"public-no-replay", []EncodeOption{generatedEncodeMarker{}, WithoutBERReplay()}, false},
		{"baseline", []EncodeOption{generatedEncodeMarker{}, replayModeOption{state: new(ReplayState), baseline: true, collector: newReplayCollector(4)}}, false},
		{"unmarked", []EncodeOption{tcapEncodeOption{}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := CanUseLinearBEREncode(test.opts); got != test.want {
				t.Fatalf("linear=%v want %v", got, test.want)
			}
		})
	}
}

func TestEncodingStructureContextResolutionDoesNotAllocate(t *testing.T) {
	options := []DecodeOption{encodingStructureOption([]byte{5, 0})}
	allocs := testing.AllocsPerRun(100, func() {
		c, err := decodeOptions(options)
		if err != nil || c.limits.MaxWork != 2 {
			panic("encoding bound lost")
		}
	})
	if allocs != 0 {
		t.Fatalf("encoding structure context allocations=%.0f, want zero", allocs)
	}
}

func TestTCAPEncodeProfileScanAllocationBound(t *testing.T) {
	wire := []byte{0x62, 3, 0x48, 1, 1}
	allocs := testing.AllocsPerRun(100, func() {
		_, finish := StageTCAPEncode(nil, "Begin", "TCAPMessages", "Begin")
		if err := finish(wire, nil); err != nil {
			panic(err)
		}
	})
	if allocs > 4 {
		t.Fatalf("TCAP encode profile scan allocations=%.0f, want at most 4", allocs)
	}
}

func TestTCAPProfileRetainsGeneratedDecodeContext(t *testing.T) {
	original := &generatedDecodeOption{
		source:    &validatedBERSource{owned: []byte{5, 0}},
		config:    decodeConfig{limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits(), profile: true, profileType: "Parent"},
		component: "child",
	}
	options := TrackTCAPForm([]DecodeOption{original}, "TCAPMessages.Child")
	if len(options) != 1 {
		t.Fatalf("profile expanded the private context into %d options", len(options))
	}
	context, ok := options[0].(*generatedDecodeOption)
	if !ok || context == original || context.source != original.source || context.component != original.component {
		t.Fatal("profile lost the detached private context")
	}
	if context.config.profileType != "TCAPMessages.Child" || !context.config.profileNested || original.config.profileType != "Parent" {
		t.Fatal("profile changed the parent or lost its source boundary")
	}
}
