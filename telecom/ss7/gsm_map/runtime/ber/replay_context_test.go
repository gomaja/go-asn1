// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_context_test.go; SHA-256 c5d127b2f49f2f52e7427f34989a0b846587496de0318ee4bce13b9f9fea6009.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sync"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestBERReplayNodesCompareBottomUp(t *testing.T) {
	// The received parent and child use indefinite lengths. The encoder below
	// writes definite lengths; the unchanged nodes must retain the received form.
	original := []byte{0x30, 0x80, 0x04, 0x81, 0x01, 0x41, 0, 0}
	state := new(ReplayState)
	child := &ReplayNode{state: state, original: append([]byte(nil), original[2:6]...)}
	root := &ReplayNode{state: state, original: append([]byte(nil), original...)}
	type value struct {
		content []byte
		child   *ReplayNode
		root    *ReplayNode
	}
	var encode func(*value, ...EncodeOption) ([]byte, error)
	encode = func(v *value, options ...EncodeOption) ([]byte, error) {
		options, err := PrepareBERReplay(v.root, options, func(mode EncodeOption) ([]byte, error) { return encode(v, mode) }, v)
		if err != nil {
			return nil, err
		}
		if replay, ok := PreparedBERReplay(v.root, options); ok {
			return replay, nil
		}
		options, err = PrepareBERReplay(v.child, options, nil, v)
		if err != nil {
			return nil, err
		}
		encodedChild := append([]byte{4, byte(len(v.content))}, v.content...)
		encodedChild = PreserveEncodedBERNode(encodedChild, v.child, options)
		encoded := append([]byte{0x30, byte(len(encodedChild))}, encodedChild...)
		return PreserveEncodedBERNode(encoded, v.root, options), nil
	}
	decoded := &value{content: []byte("A"), child: child, root: root}
	baseline := &value{content: bytes.Clone(decoded.content), child: child, root: root}
	state.setBaseline(func(option EncodeOption) ([]byte, error) {
		return encode(baseline, option)
	})

	first, err := encode(decoded)
	if err != nil || !bytes.Equal(first, original) {
		t.Fatalf("first replay = %x, %v", first, err)
	}
	first[0] = 0
	if intact, err := encode(decoded); err != nil || !bytes.Equal(intact, original) {
		t.Fatalf("caller mutated retained replay: %x, %v", intact, err)
	}
	decoded.content[0] = 'B'
	changedAllocs := testing.AllocsPerRun(100, func() {
		if _, err := encode(decoded); err != nil {
			t.Fatal(err)
		}
	})
	// Without an exact value comparison, the changed child needs a second
	// encoding to distinguish it from an alternate received BER form.
	if changedAllocs > 24 {
		t.Fatalf("changed replay allocations = %.0f, want at most 24", changedAllocs)
	}
	changed, err := encode(decoded)
	if err != nil || !bytes.Equal(changed, []byte{0x30, 0x03, 0x04, 0x01, 'B'}) {
		t.Fatalf("changed replay = %x, %v", changed, err)
	}
	decoded.content[0] = 'A'
	again, err := encode(decoded)
	if err != nil || !bytes.Equal(again, original) {
		t.Fatalf("restored replay = %x, %v", again, err)
	}
	noReplay, err := encode(decoded, WithoutBERReplay())
	if err != nil || !bytes.Equal(noReplay, []byte{0x30, 0x03, 0x04, 0x01, 'A'}) {
		t.Fatalf("without replay = %x, %v", noReplay, err)
	}
}

func TestBERReplayFastSequenceNeedsPositivePrefixProof(t *testing.T) {
	for _, tc := range []struct {
		name, baseline, current string
		childStart              int
		wantSame                bool
		wantKnown               bool
	}{
		{"received child only", "30084801016c03020100", "300a4801016c800201000000", 5, true, true},
		{"changed sibling", "30084801016c03020100", "300a4801006c800201000000", 5, false, false},
		{"explicit wrapper", "3008a006300404024142", "3009a00730810404024142", 4, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline, err := hex.DecodeString(tc.baseline)
			if err != nil {
				t.Fatal(err)
			}
			current, err := hex.DecodeString(tc.current)
			if err != nil {
				t.Fatal(err)
			}
			tagged, _, err := DecodeTag(baseline)
			if err != nil {
				t.Fatal(err)
			}
			parent, child := new(ReplayNode), new(ReplayNode)
			childRecord := &replayRecord{start: tc.childStart, end: len(baseline)}
			parentRecord := &replayRecord{start: 0, end: len(baseline), canonicalTag: tagged, tagKnown: true, children: []*replayRecord{childRecord}}
			state := &ReplayState{baselineBytes: baseline, baselineNodes: map[*ReplayNode]*replayRecord{parent: parentRecord, child: childRecord}}
			frame := replayFastFrame{replayedNode: child, replayedCount: 1, replayedOffset: tc.childStart - 2, replayedLength: len(current) - tc.childStart, placementSeen: true}
			same, known := replaySequenceWithOneReplayedChild(parent, current, frame, state)
			if same != tc.wantSame || known != tc.wantKnown {
				t.Fatalf("decision = (same %t, known %t), want (%t, %t)", same, known, tc.wantSame, tc.wantKnown)
			}
		})
	}
}

func TestBERReplayAllChangedUsesFinalEncoding(t *testing.T) {
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{4, 0x81, 1, 'A'}}
	encode := func(value byte, mode EncodeOption) ([]byte, error) {
		options := []EncodeOption{mode}
		if _, err := PrepareBERReplay(node, options, nil, nil); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{4, 1, value}, node, options), nil
	}
	state.setBaseline(func(mode EncodeOption) ([]byte, error) { return encode('A', mode) })
	options, err := PrepareBERReplay(node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode('B', mode)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if encoded, ok := PreparedBERReplay(node, options); ok {
		t.Fatalf("changed replay incorrectly prepared canonical bytes = %x", encoded)
	}
	encoded := PreserveEncodedBERNode([]byte{4, 1, 'B'}, node, options)
	if !bytes.Equal(encoded, []byte{4, 1, 'B'}) {
		t.Fatalf("final changed encoding = %x", encoded)
	}
}

func TestBERReplayLazyBaselineFailureFallsBackToFreshEncode(t *testing.T) {
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{4, 0x81, 1, 'A'}}
	state.setBaseline(func(EncodeOption) ([]byte, error) {
		return nil, errors.New("baseline unavailable")
	})
	options, err := PrepareBERReplay(node, nil, nil, nil)
	if err != nil {
		t.Fatalf("fresh encoding blocked by replay baseline: %v", err)
	}
	if !state.disabled || len(options) != 0 {
		t.Fatalf("failed baseline left replay enabled: disabled=%t options=%d", state.disabled, len(options))
	}
	encoded := PreserveEncodedBERNode([]byte{4, 1, 'B'}, node, options)
	if !bytes.Equal(encoded, []byte{4, 1, 'B'}) {
		t.Fatalf("fresh encode = %x", encoded)
	}
}

func TestBERReplayUnprovenRootChangeUsesComparison(t *testing.T) {
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{0x30, 4, 2, 0x81, 1, 1}}
	state.root = node
	state.same = func(any, *BERReplayComparisons) berValueComparison { return berValueUnknown }
	encode := func(mode EncodeOption) ([]byte, error) {
		options, err := PrepareBERReplay(node, []EncodeOption{mode}, nil, nil)
		if err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{0x30, 3, 2, 1, 1}, node, options), nil
	}
	state.setBaseline(encode)
	options, err := PrepareBERReplay(node, nil, encode, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := PreparedBERReplay(node, options)
	if !ok || !bytes.Equal(got, node.original) {
		t.Fatalf("unproven root replay = %x, available %t; want %x", got, ok, node.original)
	}
}

func TestBERReplayComparisonCanonicalizesIndefiniteForm(t *testing.T) {
	state := new(ReplayState)
	root := &ReplayNode{state: state, original: []byte{0x30, 0x0c, 2, 0x81, 1, 1, 0x30, 0x80, 2, 0x81, 1, 1, 0, 0}}
	child := &ReplayNode{state: state, original: root.original[6:]}
	grandchild := &ReplayNode{state: state, original: root.original[8:12]}
	state.root = root
	state.same = func(any, *BERReplayComparisons) berValueComparison { return berValueUnknown }
	encode := func(mode EncodeOption) ([]byte, error) {
		options, err := PrepareBERReplay(root, []EncodeOption{mode}, nil, nil)
		if err != nil {
			return nil, err
		}
		options, err = PrepareBERReplay(child, options, nil, nil)
		if err != nil {
			return nil, err
		}
		options, err = PrepareBERReplay(grandchild, options, nil, nil)
		if err != nil {
			return nil, err
		}
		encodedGrandchild := PreserveEncodedBERNode([]byte{2, 1, 1}, grandchild, options)
		RecordGeneratedBERChildPlacement(options, 0, encodedGrandchild)
		RecordGeneratedBERContainer(options, encodedGrandchild)
		var encodedChild []byte
		if BERReplayEnabled(options) {
			encodedChild = append([]byte{0x30, 0x80}, encodedGrandchild...)
			encodedChild = append(encodedChild, 0, 0)
		} else {
			encodedChild = append([]byte{0x30, byte(len(encodedGrandchild))}, encodedGrandchild...)
		}
		encodedChild = PreserveEncodedBERNode(encodedChild, child, options)
		content := append([]byte{2, 1, 1}, encodedChild...)
		RecordGeneratedBERChildPlacement(options, 3, encodedChild)
		RecordGeneratedBERContainer(options, content)
		encodedRoot := append([]byte{0x30, byte(len(content))}, content...)
		return PreserveEncodedBERNode(encodedRoot, root, options), nil
	}
	state.setBaseline(encode)
	options, err := PrepareBERReplay(root, nil, encode, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := PreparedBERReplay(root, options)
	if !ok || !bytes.Equal(got, root.original) {
		t.Fatalf("canonical comparison replay = %x, available %t; want %x", got, ok, root.original)
	}
}

func TestBERReplayKnownValueChangeUsesSingleEncode(t *testing.T) {
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{0x30, 4, 2, 0x81, 1, 1}}
	state.root = node
	state.same = func(any, *BERReplayComparisons) berValueComparison { return berValueDifferent }
	currentCalls := 0
	encode := func(value byte, mode EncodeOption) ([]byte, error) {
		if value == 2 {
			currentCalls++
		}
		options, err := PrepareBERReplay(node, []EncodeOption{mode}, nil, nil)
		if err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{0x30, 3, 2, 1, value}, node, options), nil
	}
	state.setBaseline(func(mode EncodeOption) ([]byte, error) { return encode(1, mode) })
	options, err := PrepareBERReplay(node, nil, func(mode EncodeOption) ([]byte, error) {
		return encode(2, mode)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := PreparedBERReplay(node, options); ok || currentCalls != 0 {
		t.Fatalf("changed value encoded during replay preparation: available %t, passes %d", ok, currentCalls)
	}
	got, err := encode(2, options[0])
	if err != nil || !bytes.Equal(got, []byte{0x30, 3, 2, 1, 2}) || currentCalls != 1 {
		t.Fatalf("known changed replay = %x, current passes %d; want one pass: %v", got, currentCalls, err)
	}
}

func TestReplayNodeComparisonsInlineAndOverflow(t *testing.T) {
	claims := new(BERReplayComparisons)
	for index := uintptr(1); index <= 24; index++ {
		claims.put(index, berValueEqual)
	}
	claims.put(1, berValueDifferent)
	claims.put(24, berValueDifferent)
	if claims.count != 12 || len(claims.overflow) != 12 {
		t.Fatalf("comparison storage = %d inline, %d overflow", claims.count, len(claims.overflow))
	}
	for index := uintptr(1); index <= 24; index++ {
		want := berValueEqual
		if index == 1 || index == 24 {
			want = berValueDifferent
		}
		if got, ok := claims.get(index); !ok || got != want {
			t.Fatalf("claim %d = %v, found %t, want %v", index, got, ok, want)
		}
	}
	if _, ok := claims.get(25); ok {
		t.Fatal("missing node was reported present")
	}
}

func TestCloneBERValueKeepsReplayIdentityAndCopiesMutableValues(t *testing.T) {
	type value struct {
		Bytes []byte
		Big   *big.Int
		Node  *ReplayNode
	}
	node := new(ReplayNode)
	current := &value{Bytes: []byte{1}, Big: big.NewInt(7), Node: node}
	copyValue, err := CloneBERValue(current)
	if err != nil {
		t.Fatal(err)
	}
	baseline := copyValue.(*value)
	current.Bytes[0] = 2
	current.Big.SetInt64(8)
	if baseline.Bytes[0] != 1 || baseline.Big.Int64() != 7 || baseline.Node != node {
		t.Fatalf("baseline changed with current value: %+v", baseline)
	}
}

func TestBERValueEqualityDetectsNestedMutation(t *testing.T) {
	type element struct {
		Bytes []byte
		Count *big.Int
	}
	type value struct{ Elements []*element }
	current := &value{Elements: []*element{{Bytes: []byte{'A'}, Count: big.NewInt(7)}}}
	copyValue, err := CloneBERValue(current)
	if err != nil {
		t.Fatal(err)
	}
	baseline := copyValue.(*value)
	equal := func() bool { return equalBERValue(reflect.ValueOf(current), reflect.ValueOf(baseline), 0) }
	if !equal() {
		t.Fatal("equal detached values compared different")
	}
	current.Elements[0].Bytes[0] = 'B'
	if equal() {
		t.Fatal("nested byte mutation was missed")
	}
	current.Elements[0].Bytes[0] = 'A'
	current.Elements[0].Count.SetInt64(8)
	if equal() {
		t.Fatal("nested integer mutation was missed")
	}
	current.Elements[0].Count.SetInt64(7)
	if !equal() {
		t.Fatal("restored value compared different")
	}
	type cycle struct{ Next *cycle }
	one, two := new(cycle), new(cycle)
	one.Next, two.Next = one, two
	if equalBERValue(reflect.ValueOf(one), reflect.ValueOf(two), 0) {
		t.Fatal("cyclic values claimed equal without proof")
	}
	if got := compareBERValue(reflect.ValueOf(one), reflect.ValueOf(two), 0); got != berValueUnknown {
		t.Fatalf("cyclic value comparison = %v, want unknown", got)
	}
	type hidden struct{ data []byte }
	if equalBERValue(reflect.ValueOf(hidden{[]byte{1}}), reflect.ValueOf(hidden{[]byte{2}}), 0) {
		t.Fatal("unexported byte mutation was missed")
	}
}

func TestBERValueEqualityUsesValueRepresentations(t *testing.T) {
	type value struct {
		Number *big.Int
		Data   []byte
		Items  []string
	}
	decoded := &value{Number: new(big.Int).SetBytes([]byte{0}), Data: []byte{}, Items: []string{}}
	cloned, err := CloneBERValue(decoded)
	if err != nil {
		t.Fatal(err)
	}
	baseline := cloned.(*value)
	check := func(want bool) {
		t.Helper()
		if got := equalBERValue(reflect.ValueOf(decoded), reflect.ValueOf(baseline), 0); got != want {
			t.Fatalf("value equality = %t, want %t", got, want)
		}
		wantComparison := berValueDifferent
		if want {
			wantComparison = berValueEqual
		}
		if got := compareBERValue(reflect.ValueOf(decoded), reflect.ValueOf(baseline), 0); got != wantComparison {
			t.Fatalf("value comparison = %v, want %v", got, wantComparison)
		}
	}
	check(true)
	decoded.Number = big.NewInt(0)
	decoded.Data = nil
	decoded.Items = nil
	check(true)
	decoded.Number.SetInt64(1)
	check(false)
	decoded.Number.SetInt64(0)
	decoded.Data = []byte{1}
	check(false)
}

func TestBERReplayNodeIdentityDoesNotProveValueChange(t *testing.T) {
	first, second := new(ReplayNode), new(ReplayNode)
	if got := compareBERValue(reflect.ValueOf(first), reflect.ValueOf(first), 0); got != berValueEqual {
		t.Fatalf("same replay node comparison = %v, want equal", got)
	}
	if got := compareBERValue(reflect.ValueOf(first), reflect.ValueOf(second), 0); got != berValueUnknown {
		t.Fatalf("different replay node comparison = %v, want unknown", got)
	}
}

func TestBERReplayTypedNodeDifferencesFollowValueFields(t *testing.T) {
	type leaf struct {
		Value          int
		berReplayNode_ *ReplayNode `asn1:"-"`
	}
	type root struct {
		Left           leaf
		Right          leaf
		berReplayNode_ *ReplayNode `asn1:"-"`
	}
	rootNode, leftNode, rightNode := new(ReplayNode), new(ReplayNode), new(ReplayNode)
	baseline := root{Left: leaf{Value: 1, berReplayNode_: leftNode}, Right: leaf{Value: 2, berReplayNode_: rightNode}, berReplayNode_: rootNode}
	current := baseline
	current.Left.Value = 3
	nodes := new(BERReplayComparisons)
	if got := compareBERValueNodes(reflect.ValueOf(&current), reflect.ValueOf(&baseline), 0, nodes); got != berValueDifferent {
		t.Fatalf("root comparison = %v, want different", got)
	}
	for _, tc := range []struct {
		name string
		node *ReplayNode
		want berValueComparison
	}{
		{"root", rootNode, berValueDifferent},
		{"changed child", leftNode, berValueDifferent},
		{"unchanged child", rightNode, berValueEqual},
	} {
		if got, _ := nodes.get(reflect.ValueOf(tc.node).Pointer()); got != tc.want {
			t.Errorf("%s comparison = %v, want %v", tc.name, got, tc.want)
		}
	}
	swapped := baseline
	swapped.Left, swapped.Right = swapped.Right, swapped.Left
	swappedNodes := new(BERReplayComparisons)
	if got := compareBERValueNodes(reflect.ValueOf(&swapped), reflect.ValueOf(&baseline), 0, swappedNodes); got != berValueDifferent {
		t.Fatalf("swapped root comparison = %v, want different", got)
	}
	for _, node := range []*ReplayNode{leftNode, rightNode} {
		if got, ok := swappedNodes.get(reflect.ValueOf(node).Pointer()); ok {
			t.Errorf("moved node received positional comparison %v", got)
		}
	}
}

func TestBERValueComparisonTreatsRepresentationAsUncertain(t *testing.T) {
	type withForm struct {
		Value int
		Form  bool `asn1:"-"`
	}
	for name, pair := range map[string][2]any{
		"generated form": {withForm{Value: 1}, withForm{Value: 1, Form: true}},
	} {
		if got := compareBERValue(reflect.ValueOf(pair[0]), reflect.ValueOf(pair[1]), 0); got != berValueUnknown {
			t.Errorf("%s comparison = %v, want unknown", name, got)
		}
	}
	if got := compareBERValue(reflect.ValueOf(runtime.RawValue{Tag: 2, Bytes: []byte{1}}), reflect.ValueOf(runtime.RawValue{Tag: 2, Bytes: []byte{0, 1}}), 0); got != berValueDifferent {
		t.Errorf("open value bytes comparison = %v, want different", got)
	}
	first := runtime.External{Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{1}}
	second := first
	first.RememberBER([]byte{0x28, 3, 0x81, 1, 1})
	second.RememberBER([]byte{0x28, 0x81, 3, 0x81, 1, 1})
	if got := compareBERValue(reflect.ValueOf(first), reflect.ValueOf(second), 0); got != berValueUnknown {
		t.Errorf("EXTERNAL received forms comparison = %v, want unknown", got)
	}
	bits1 := runtime.BitString{Bytes: []byte{0xe1}, BitLength: 3}
	bits2 := runtime.BitString{Bytes: []byte{0xe0}, BitLength: 3}
	if got := compareBERValue(reflect.ValueOf(bits1), reflect.ValueOf(bits2), 0); got != berValueUnknown {
		t.Errorf("BIT STRING unused bits comparison = %v, want unknown", got)
	}
}

func TestBERComparisonEncodingSkipsRetainedForms(t *testing.T) {
	mode := replayModeOption{state: new(ReplayState), comparison: true}
	canonical := []byte{0x02, 1, 1}
	received := []byte{0x02, 0x81, 1, 1}
	if got := PreserveEncodedBER(canonical, received, canonical, []EncodeOption{mode}); !bytes.Equal(got, canonical) {
		t.Errorf("primitive comparison form = %x, want %x", got, canonical)
	}
	externalCanonical := []byte{0x28, 6, 6, 1, 0x2a, 0x81, 1, 'A'}
	externalReceived := []byte{0x28, 0x81, 6, 6, 1, 0x2a, 0x81, 1, 'A'}
	value, _, err := DecodeExternal(externalCanonical)
	if err != nil {
		t.Fatal(err)
	}
	value.RememberBER(externalReceived)
	got, err := EncodeExternal(value, mode)
	if err != nil || !bytes.Equal(got, externalCanonical) {
		t.Errorf("EXTERNAL comparison form = %x, want %x: %v", got, externalCanonical, err)
	}
}

func TestBERValueComparisonDistinguishesRealSpecialValues(t *testing.T) {
	left := reflect.ValueOf(math.NaN())
	right := reflect.ValueOf(math.NaN())
	if got := compareBERValue(left, right, 0); got != berValueEqual {
		t.Fatalf("NaN value comparison = %v, want equal", got)
	}
	if got := compareBERValue(reflect.ValueOf(math.Copysign(0, -1)), reflect.ValueOf(float64(0)), 0); got != berValueDifferent {
		t.Fatalf("minus-zero value comparison = %v, want different", got)
	}
}

func TestBERValueEqualityScalesWithInput(t *testing.T) {
	type element struct{ Bytes []byte }
	measure := func(count int) (float64, float64) {
		current := make([]element, count)
		baseline := make([]element, count)
		for index := range current {
			current[index].Bytes = []byte{byte(index)}
			baseline[index].Bytes = []byte{byte(index)}
		}
		check := func() {
			if !equalBERValue(reflect.ValueOf(current), reflect.ValueOf(baseline), 0) {
				t.Fatal("equal values compared different")
			}
		}
		check()
		allocs := testing.AllocsPerRun(5, check)
		benchmark := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				check()
			}
		})
		return allocs, float64(benchmark.NsPerOp())
	}
	smallAllocs, smallTime := measure(100)
	largeAllocs, largeTime := measure(2000)
	if largeAllocs > smallAllocs*5+10 {
		t.Fatalf("equality allocations grew from %.0f to %.0f", smallAllocs, largeAllocs)
	}
	if largeTime > smallTime*100 {
		t.Fatalf("equality time grew from %.0f to %.0f ns", smallTime, largeTime)
	}
}

func TestCloneBERValueAllocationsScaleLinearly(t *testing.T) {
	type element struct{ Contents []byte }
	measure := func(count int) float64 {
		value := make([]element, count)
		for index := range value {
			value[index].Contents = []byte{byte(index)}
		}
		return testing.AllocsPerRun(3, func() {
			if _, err := CloneBERValue(value); err != nil {
				t.Fatal(err)
			}
		})
	}
	small, large := measure(10), measure(2000)
	if large > small*250 {
		t.Fatalf("clone allocations: 10 elements %.0f, 2000 elements %.0f", small, large)
	}
}

func TestGeneratedReplayDoesNotEncodeDuringDecode(t *testing.T) {
	type value struct {
		Contents []byte
		Node     *ReplayNode
	}
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{4, 1, 'A'}}
	state.root = node
	context := &generatedDecodeOption{source: &validatedBERSource{owned: node.original, replay: state}}
	decoded := &value{Contents: []byte{'A'}, Node: node}
	encodes := 0
	encode := func(v *value, options ...EncodeOption) ([]byte, error) {
		encodes++
		if _, err := PrepareBERReplay(v.Node, options, nil, v); err != nil {
			return nil, err
		}
		encoded := []byte{4, 1, v.Contents[0]}
		return PreserveEncodedBERNode(encoded, v.Node, options), nil
	}
	if err := CompleteGeneratedBERDecode([]DecodeOption{context}, decoded, encode); err != nil {
		t.Fatal(err)
	}
	if encodes != 0 {
		t.Fatalf("decode encoded the baseline %d times", encodes)
	}
	prepared, err := PrepareBERReplay(node, nil, func(option EncodeOption) ([]byte, error) {
		return encode(decoded, option)
	}, decoded)
	if err != nil || encodes != 0 {
		t.Fatalf("unchanged first replay performed %d encodes: %v", encodes, err)
	}
	if replay, ok := PreparedBERReplay(node, prepared); !ok || !bytes.Equal(replay, node.original) {
		t.Fatalf("prepared replay = %x, enabled %t", replay, ok)
	}
}

func TestGeneratedTolerantDecodeStillChecksStrictEncode(t *testing.T) {
	type value struct{ Node *ReplayNode }
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{4, 1, 'A'}}
	decoded := &value{Node: node}
	context := &generatedDecodeOption{source: &validatedBERSource{owned: node.original, replay: state}, config: decodeConfig{tolerant: true, limits: DefaultDecodeLimits(), diagnostics: DefaultDiagnosticLimits()}}
	encode := func(v *value, options ...EncodeOption) ([]byte, error) {
		config, err := encodeOptions(options)
		if err != nil {
			return nil, err
		}
		if !config.tolerant {
			return nil, ErrInvalidValue
		}
		if _, err := PrepareBERReplay(v.Node, options, nil, v); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode([]byte{4, 1, 'A'}, v.Node, options), nil
	}
	if err := CompleteGeneratedBERDecode([]DecodeOption{context}, decoded, encode); err != nil {
		t.Fatal(err)
	}
	if !state.decodeTolerant || state.same == nil {
		t.Fatal("tolerant decode lost its strict validation state")
	}
	_, err := PrepareBERReplay(node, nil, func(option EncodeOption) ([]byte, error) { return encode(decoded, option) }, decoded)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("strict encode error = %v, want ErrInvalidValue", err)
	}
}

func TestBERReplayStateConcurrentFirstEncode(t *testing.T) {
	state := new(ReplayState)
	node := &ReplayNode{state: state, original: []byte{0x04, 0x81, 0x01, 'A'}}
	canonical := []byte{0x04, 0x01, 'A'}
	state.setBaseline(func(option EncodeOption) ([]byte, error) {
		if _, err := PrepareBERReplay(node, []EncodeOption{option}, nil, nil); err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(canonical, node, []EncodeOption{option}), nil
	})
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			options, err := PrepareBERReplay(node, nil, func(option EncodeOption) ([]byte, error) {
				if _, err := PrepareBERReplay(node, []EncodeOption{option}, nil, nil); err != nil {
					return nil, err
				}
				return PreserveEncodedBERNode(canonical, node, []EncodeOption{option}), nil
			}, nil)
			if err != nil {
				failures <- err
				return
			}
			encoded := PreserveEncodedBERNode(canonical, node, options)
			if !bytes.Equal(encoded, node.original) {
				failures <- fmt.Errorf("concurrent replay = %x", encoded)
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestBERReplayComparisonStorageIsLinearAtDepth(t *testing.T) {
	type nested struct {
		child *nested
		node  *ReplayNode
	}
	state := new(ReplayState)
	var root *nested
	for range DefaultDecodeLimits().MaxDepth {
		root = &nested{child: root, node: &ReplayNode{state: state, original: []byte{0x30, 0}}}
	}
	var encode func(*nested, ...EncodeOption) ([]byte, error)
	encode = func(value *nested, options ...EncodeOption) ([]byte, error) {
		var err error
		options, err = PrepareBERReplay(value.node, options, func(mode EncodeOption) ([]byte, error) { return encode(value, mode) }, value)
		if err != nil {
			return nil, err
		}
		var content []byte
		if value.child != nil {
			content, err = encode(value.child, options...)
			if err != nil {
				return nil, err
			}
		} else {
			content = []byte{0x04, 0x01, 'A'}
		}
		encoded, err := EncodeSequence(content)
		if err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(encoded, value.node, options), nil
	}
	state.setBaseline(func(option EncodeOption) ([]byte, error) {
		return encode(root, option)
	})
	if _, err := PrepareBERReplay(root.node, nil, func(option EncodeOption) ([]byte, error) { return encode(root, option) }, root); err != nil {
		t.Fatal(err)
	}
	canonical, err := encode(root, WithoutBERReplay())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.baselineBytes) > len(canonical) {
		t.Fatalf("comparison storage = %d bytes for a %d-byte encoding", len(state.baselineBytes), len(canonical))
	}
	if len(state.baselineNodes) != DefaultDecodeLimits().MaxDepth {
		t.Fatalf("comparison records = %d, want %d", len(state.baselineNodes), DefaultDecodeLimits().MaxDepth)
	}
	for _, record := range state.baselineNodes {
		if record.pending != nil || record.start < 0 || record.end > len(state.baselineBytes) || record.start >= record.end {
			t.Fatalf("invalid retained comparison record: %+v", record)
		}
	}
}

func TestBERReplayPlacementIgnoresTLVBytesInsidePrimitiveContent(t *testing.T) {
	parent := []byte{0x04, 0x05, 0x80, 0x03, 'A', 'B', 'C'}
	child := []byte{0x04, 0x03, 'A', 'B', 'C'}
	if offset, _ := replayChildAtPosition(parent, child); offset >= 0 {
		t.Fatalf("primitive contents were mistaken for a retagged child at offset %d", offset)
	}
	retagged := []byte{0x80, 0x03, 'A', 'B', 'C'}
	if offset, length := replayChildAtPosition(retagged, child); offset != 0 || length != 5 {
		t.Fatalf("retagged child range = (%d, %d), want (0, 5)", offset, length)
	}
	definite := []byte{0xa4, 0x03, 0x04, 0x01, 'A'}
	indefinite := []byte{0xa4, 0x80, 0x04, 0x01, 'A', 0, 0}
	if offset, length := replayChildAtPosition(indefinite, definite); offset != 0 || length != 7 {
		t.Fatalf("indefinite child range = (%d, %d), want (0, 7)", offset, length)
	}
}

func TestBERReplayLookupAcceptsEncoderOutputAboveDefaultWorkLimit(t *testing.T) {
	contents := bytes.Repeat([]byte{0x5a}, DefaultDecodeLimits().MaxWork+1)
	childLength := EncodeLength(len(contents))
	child := append(append([]byte{0x04}, childLength...), contents...)
	if offset, length := replayChildAtPosition(child, child); offset != 0 || length != len(child) {
		t.Fatalf("large child range = (%d, %d), want (0, %d)", offset, length, len(child))
	}
}

func TestBERReplayChildMappingRequiresElementBoundary(t *testing.T) {
	state := new(ReplayState)
	parent := &ReplayNode{state: state}
	child := &ReplayNode{state: state}
	collector := new(replayCollector)
	collector.enter(parent)
	collector.enter(child)
	collector.leave(child, []byte{0x04, 0x03, 'A', 'B', 'C'})
	collector.leave(parent, []byte{0x04, 0x05, 0x04, 0x03, 'A', 'B', 'C'})
	if err := collector.finish([]byte{0x04, 0x05, 0x04, 0x03, 'A', 'B', 'C'}); err != nil {
		t.Fatal(err)
	}
	if collector.nodes[child].start >= 0 {
		t.Fatal("TLV-shaped primitive contents were accepted as a generated child")
	}
}

func TestBERReplayChildMappingPrefersExactLaterElement(t *testing.T) {
	state := new(ReplayState)
	parentNode := &ReplayNode{state: state}
	childNode := &ReplayNode{state: state}
	child := []byte{0xa4, 0x03, 0x04, 0x01, 'A'}
	parent := []byte{0x30, 0x0c, 0xa4, 0x80, 0x04, 0x01, 'A', 0, 0, 0xa4, 0x03, 0x04, 0x01, 'A'}
	collector := new(replayCollector)
	collector.enter(parentNode)
	collector.enter(childNode)
	collector.leave(childNode, child)
	RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, 7, parent[9:])
	RecordGeneratedBERContainer([]EncodeOption{replayModeOption{state: state, collector: collector}}, parent[2:])
	collector.leave(parentNode, parent)
	if err := collector.finish(parent); err != nil {
		t.Fatal(err)
	}
	if got := collector.nodes[childNode].start; got != 9 {
		t.Fatalf("child offset = %d, want 9", got)
	}
}

func TestBERReplayChildMappingUsesReceivedTag(t *testing.T) {
	state := new(ReplayState)
	parentNode := &ReplayNode{state: state}
	wireTag, _, err := DecodeTag([]byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	childNode := &ReplayNode{state: state, wireTag: wireTag, wireTagKnown: true}
	child := []byte{0xa4, 0x03, 0x04, 0x01, 'A'}
	parent := []byte{0x30, 0x0e, 0xa4, 0x80, 0x04, 0x01, 'A', 0, 0, 0xa5, 0x80, 0x04, 0x01, 'A', 0, 0}
	collector := new(replayCollector)
	collector.enter(parentNode)
	collector.enter(childNode)
	collector.leave(childNode, child)
	RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, 7, parent[9:])
	RecordGeneratedBERContainer([]EncodeOption{replayModeOption{state: state, collector: collector}}, parent[2:])
	collector.leave(parentNode, parent)
	if err := collector.finish(parent); err != nil {
		t.Fatal(err)
	}
	if got := collector.nodes[childNode].start; got != 9 {
		t.Fatalf("retagged child offset = %d, want 9", got)
	}
}

func TestBERReplayChildMappingAcceptsImplicitRetag(t *testing.T) {
	state := new(ReplayState)
	parentNode := &ReplayNode{state: state}
	child := []byte{0xbf, 0x41, 0x03, 0x80, 0x01, 0x01}
	wireTag, _, err := DecodeTag(child)
	if err != nil {
		t.Fatal(err)
	}
	childNode := &ReplayNode{state: state, wireTag: wireTag, wireTagKnown: true}
	parent := []byte{0xa4, 0x03, 0x80, 0x01, 0x01}
	collector := new(replayCollector)
	collector.enter(parentNode)
	collector.enter(childNode)
	collector.leave(childNode, child)
	collector.leave(parentNode, parent)
	if err := collector.finish(parent); err != nil {
		t.Fatal(err)
	}
	if record := collector.nodes[childNode]; record.start != 0 || record.end != len(parent) {
		t.Fatalf("implicit child range = [%d,%d), want [0,%d)", record.start, record.end, len(parent))
	}
}

func TestBERReplayIndexedChildMappingPrefersReceivedTag(t *testing.T) {
	state := new(ReplayState)
	parentNode := &ReplayNode{state: state}
	wireTag, _, err := DecodeTag([]byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	first := &ReplayNode{state: state, wireTag: wireTag, wireTagKnown: true}
	second := &ReplayNode{state: state, wireTag: wireTag, wireTagKnown: true}
	parent := []byte{0x30, 0x14,
		0xa3, 0x04, 0x04, 0x02, 0x00, 0x00,
		0xa4, 0x80, 0x04, 0x01, 'A', 0, 0,
		0xa5, 0x80, 0x04, 0x01, 'A', 0, 0}
	collector := new(replayCollector)
	collector.enter(parentNode)
	collector.enter(first)
	collector.leave(first, []byte{0xa4, 0x04, 0x04, 0x02, 0, 0})
	RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, 0, parent[2:8])
	collector.enter(second)
	collector.leave(second, []byte{0xa4, 0x03, 0x04, 0x01, 'A'})
	RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, 13, parent[15:])
	RecordGeneratedBERContainer([]EncodeOption{replayModeOption{state: state, collector: collector}}, parent[2:])
	collector.leave(parentNode, parent)
	if err := collector.finish(parent); err != nil {
		t.Fatal(err)
	}
	if got := collector.nodes[second].start; got != 15 {
		t.Fatalf("indexed child offset = %d, want 15", got)
	}
}

func TestGeneratedReplayTagHintExcludesReconstructedInput(t *testing.T) {
	wire := []byte{0xa5, 0x01, 'A'}
	state := new(ReplayState)
	source := &validatedBERSource{owned: wire, replay: state}
	owned := CaptureGeneratedBERReplay(wire, []DecodeOption{&generatedDecodeOption{source: source}})
	if owned == nil || !owned.wireTagKnown {
		t.Fatal("validated wire tag was not retained")
	}
	source.reconstructed = true
	reconstructed := CaptureGeneratedBERReplay(wire, []DecodeOption{&generatedDecodeOption{source: source}})
	if reconstructed == nil || reconstructed.wireTagKnown {
		t.Fatal("reconstructed universal tag was mistaken for a wire tag")
	}
}

func TestBERReplayUniqueAlternateChildrenScaleWithInput(t *testing.T) {
	measure := func(count int) (float64, float64) {
		check := func() {
			state := new(ReplayState)
			parentNode := &ReplayNode{state: state}
			collector := new(replayCollector)
			collector.enter(parentNode)
			contents := make([]byte, 0, count*8)
			for index := range count {
				childNode := &ReplayNode{state: state}
				collector.enter(childNode)
				collector.leave(childNode, []byte{0xa4, 0x04, 0x04, 0x02, byte(index >> 8), byte(index)})
				start := len(contents)
				contents = append(contents, 0xa4, 0x80, 0x04, 0x02, byte(index>>8), byte(index), 0, 0)
				RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, start, contents[start:])
			}
			parent, err := EncodeSequence(contents)
			if err != nil {
				t.Fatal(err)
			}
			RecordGeneratedBERContainer([]EncodeOption{replayModeOption{state: state, collector: collector}}, contents)
			collector.leave(parentNode, parent)
			if err := collector.finish(parent); err != nil {
				t.Fatal(err)
			}
		}
		check()
		benchmark := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				check()
			}
		})
		return float64(benchmark.NsPerOp()), float64(benchmark.AllocedBytesPerOp())
	}
	smallTime, smallBytes := measure(100)
	largeTime, largeBytes := measure(2000)
	t.Logf("unique alternate mapping: time %.1fx, allocated bytes %.1fx for 20x input", largeTime/smallTime, largeBytes/smallBytes)
	if largeTime > smallTime*100 || largeBytes > smallBytes*100 {
		t.Fatalf("unique alternate mapping grew from %.0f ns and %.0f B to %.0f ns and %.0f B", smallTime, smallBytes, largeTime, largeBytes)
	}
}

func TestBERReplayUniqueImplicitChildrenScaleWithInput(t *testing.T) {
	wireTag, _, err := DecodeTag([]byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	measure := func(count int) float64 {
		check := func() {
			state := new(ReplayState)
			parentNode := &ReplayNode{state: state}
			collector := new(replayCollector)
			collector.enter(parentNode)
			contents := make([]byte, 0, count*6)
			for index := range count {
				childNode := &ReplayNode{state: state, wireTag: wireTag, wireTagKnown: true}
				collector.enter(childNode)
				collector.leave(childNode, []byte{0xa4, 0x04, 0x04, 0x02, byte(index >> 8), byte(index)})
				start := len(contents)
				contents = append(contents, 0xa3, 0x04, 0x04, 0x02, byte(index>>8), byte(index))
				RecordGeneratedBERChildPlacement([]EncodeOption{replayModeOption{state: state, collector: collector}}, start, contents[start:])
			}
			parent, err := EncodeSequence(contents)
			if err != nil {
				t.Fatal(err)
			}
			RecordGeneratedBERContainer([]EncodeOption{replayModeOption{state: state, collector: collector}}, contents)
			collector.leave(parentNode, parent)
			if err := collector.finish(parent); err != nil {
				t.Fatal(err)
			}
		}
		check()
		benchmark := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				check()
			}
		})
		return float64(benchmark.NsPerOp())
	}
	small, large := measure(100), measure(2000)
	t.Logf("implicit child mapping: time %.1fx for 20x input", large/small)
	if large > small*100 {
		t.Fatalf("implicit child mapping grew from %.0f ns to %.0f ns", small, large)
	}
}

func BenchmarkBERReplayNestedDepth(b *testing.B) {
	type nested struct {
		child *nested
		node  *ReplayNode
	}
	var encode func(*nested, ...EncodeOption) ([]byte, error)
	encode = func(value *nested, options ...EncodeOption) ([]byte, error) {
		var err error
		options, err = PrepareBERReplay(value.node, options, func(mode EncodeOption) ([]byte, error) { return encode(value, mode) }, value)
		if err != nil {
			return nil, err
		}
		var content []byte
		if value.child != nil {
			content, err = encode(value.child, options...)
			if err != nil {
				return nil, err
			}
		} else {
			content = []byte{0x04, 0x01, 'A'}
		}
		encoded, err := EncodeSequence(content)
		if err != nil {
			return nil, err
		}
		return PreserveEncodedBERNode(encoded, value.node, options), nil
	}
	for _, depth := range []int{1, 10, 100, DefaultDecodeLimits().MaxDepth} {
		b.Run(fmt.Sprintf("Depth%d", depth), func(b *testing.B) {
			var root *nested
			for range depth {
				root = &nested{child: root, node: &ReplayNode{original: []byte{0x30, 0}}}
			}
			canonical, err := encode(root, WithoutBERReplay())
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(canonical)))
			b.ReportAllocs()
			for b.Loop() {
				state := new(ReplayState)
				for value := root; value != nil; value = value.child {
					value.node.state = state
				}
				state.setBaseline(func(option EncodeOption) ([]byte, error) { return encode(root, option) })
				if _, err := encode(root); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestBERReplayOptionResolutionDoesNotAllocate(t *testing.T) {
	state := new(ReplayState)
	options := []EncodeOption{replayModeOption{state: state, baseline: true}}
	config, err := encodeOptions(options)
	if err != nil || !config.tolerant || config.violations != &state.sink {
		t.Fatalf("baseline replay policy = %+v, %v", config, err)
	}
	collector := new(replayCollector)
	config, err = encodeOptions([]EncodeOption{replayModeOption{state: state, collector: collector}})
	if err != nil || !config.tolerant || config.violations != &collector.sink {
		t.Fatalf("current comparison policy = %+v, %v", config, err)
	}
	if BERReplayEnabled([]EncodeOption{replayModeOption{state: state, collector: collector}}) {
		t.Fatal("canonical comparison reused received primitive form")
	}
	if BERReplayEnabled([]EncodeOption{replayModeOption{state: state, comparison: true}}) {
		t.Fatal("canonical comparison reused received primitive form")
	}
	if _, err := encodeOptions([]EncodeOption{replayModeOption{baseline: true}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid replay state = %v", err)
	}
	allocated := testing.AllocsPerRun(100, func() {
		if _, err := encodeOptions(options); err != nil {
			t.Fatal(err)
		}
	})
	if allocated != 0 {
		t.Fatalf("replay option resolution allocated %.0f objects", allocated)
	}
}
