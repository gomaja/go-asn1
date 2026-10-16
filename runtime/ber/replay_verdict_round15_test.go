package ber

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
)

func TestBERReplayOpaqueAndPresenceVerdicts(t *testing.T) {
	one := 1
	for _, tc := range []struct {
		name   string
		before any
		after  any
		want   berValueComparison
	}{
		{"opaque bytes", runtime.RawValue{Bytes: []byte{2, 1, 1}}, runtime.RawValue{Bytes: []byte{2, 1, 2}}, berValueDifferent},
		{"opaque header", runtime.RawValue{Tag: 2, Bytes: []byte{2, 1, 1}}, runtime.RawValue{Tag: 3, Bytes: []byte{2, 1, 1}}, berValueUnknown},
		{"opaque retagged identifier only", runtime.RawValue{Bytes: []byte{2, 1, 1}}, runtime.RawValue{Bytes: []byte{3, 1, 1}}, berValueUnknown},
		{"opaque constructed bit", runtime.RawValue{Bytes: []byte{2, 1, 1}}, runtime.RawValue{Bytes: []byte{0x22, 1, 1}}, berValueDifferent},
		{"null pointers", struct{ Value *struct{} }{new(struct{})}, struct{ Value *struct{} }{new(struct{})}, berValueEqual},
		{"null under edited parent", struct {
			Value *struct{}
			X     int
		}{new(struct{}), 1}, struct {
			Value *struct{}
			X     int
		}{new(struct{}), 2}, berValueDifferent},
		{"extension bytes", struct {
			ExtData_ [][]byte `asn1:"-"`
		}{[][]byte{{0x80, 1, 1}}}, struct {
			ExtData_ [][]byte `asn1:"-"`
		}{[][]byte{{0x80, 1, 2}}}, berValueDifferent},
		{"other bookkeeping", struct {
			Other_ [][]byte `asn1:"-"`
		}{[][]byte{{1}}}, struct {
			Other_ [][]byte `asn1:"-"`
		}{[][]byte{{2}}}, berValueUnknown},
		{"optional pointer added", struct {
			Value *int `asn1:"tag:0,optional"`
		}{}, struct {
			Value *int `asn1:"tag:0,optional"`
		}{&one}, berValueDifferent},
		{"optional empty slice added", struct {
			Value []byte `asn1:"tag:0,optional"`
		}{}, struct {
			Value []byte `asn1:"tag:0,optional"`
		}{[]byte{}}, berValueDifferent},
		{"default pointer added", struct {
			Value *int `asn1:"tag:0,optional"`
		}{}, struct {
			Value *int `asn1:"tag:0,optional"`
		}{&one}, berValueDifferent},
		{"default empty slice added", struct {
			Value []byte `asn1:"tag:0,optional"`
		}{}, struct {
			Value []byte `asn1:"tag:0,optional"`
		}{[]byte{}}, berValueDifferent},
		{"optional empty list added", struct {
			Value []int `asn1:"tag:0,optional"`
		}{}, struct {
			Value []int `asn1:"tag:0,optional"`
		}{[]int{}}, berValueDifferent},
		{"optional big integer added", struct {
			Value *big.Int `asn1:"tag:0,optional"`
		}{}, struct {
			Value *big.Int `asn1:"tag:0,optional"`
		}{big.NewInt(0)}, berValueDifferent},
		{"required nil and empty octets", struct {
			Value []byte `asn1:"tag:0"`
		}{}, struct {
			Value []byte `asn1:"tag:0"`
		}{[]byte{}}, berValueEqual},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compareBERValue(reflect.ValueOf(tc.before), reflect.ValueOf(tc.after), 0)
			if got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBERReplayChoiceComparesNamedAlternatives(t *testing.T) {
	type child struct{ Data []byte }
	type pick struct {
		Choice           int
		berReplayNode_   *ReplayNode
		UnknownExtension *runtime.BERChoiceExtension
		Octets           []byte
		Kid              *child
	}
	type alias pick
	type outer struct{ Inner pick }
	for _, tc := range []struct {
		name          string
		before, after pick
		want          berValueComparison
	}{
		{"octets-edit", pick{Choice: 1, Octets: []byte("ABC")}, pick{Choice: 1, Octets: []byte("XYZ")}, berValueDifferent},
		{"kid-edit", pick{Choice: 2, Kid: &child{[]byte("A")}}, pick{Choice: 2, Kid: &child{[]byte("B")}}, berValueDifferent},
		{"stale-unknown-extension", pick{Choice: 1, UnknownExtension: &runtime.BERChoiceExtension{}, Octets: []byte("ABC")}, pick{Choice: 1, Octets: []byte("XYZ")}, berValueUnknown},
		{"both-selected-added", pick{Choice: 1, Octets: []byte("ABC")}, pick{Choice: 1, UnknownExtension: &runtime.BERChoiceExtension{Element: []byte{0x82, 1, 7}}, Octets: []byte("ABC")}, berValueUnknown},
		{"both-selected-removed", pick{Choice: 1, UnknownExtension: &runtime.BERChoiceExtension{}, Octets: []byte("ABC")}, pick{Choice: 1, Octets: []byte("ABC")}, berValueUnknown},
		{"unselected-edit", pick{Choice: 2, Kid: &child{[]byte("A")}}, pick{Choice: 2, Octets: []byte("XYZ"), Kid: &child{[]byte("A")}}, berValueEqual},
		{"unknown-choice", pick{Choice: 0}, pick{Choice: 0}, berValueUnknown},
		{"unknown-to-known", pick{Choice: 0}, pick{Choice: 1, Octets: []byte("XYZ")}, berValueUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := new(ReplayNode)
			tc.before.berReplayNode_, tc.after.berReplayNode_ = shared, shared
			if got := compareBERValue(reflect.ValueOf(tc.after), reflect.ValueOf(tc.before), 0); got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("unknownExtension-is-a-known-alternative", func(t *testing.T) {
		type clash struct {
			Choice           int
			berReplayNode_   *ReplayNode
			UnknownExtension []byte
			Kid              *child
		}
		shared := new(ReplayNode)
		before := clash{Choice: 1, berReplayNode_: shared, UnknownExtension: []byte("ABC")}
		after := clash{Choice: 1, berReplayNode_: shared, UnknownExtension: []byte("XYZ")}
		if got := compareBERValue(reflect.ValueOf(after), reflect.ValueOf(before), 0); got != berValueDifferent {
			t.Fatalf("verdict = %v, want different", got)
		}
	})
	for _, tc := range []struct {
		name          string
		before, after any
	}{
		{"alias-octets-edit", alias{Choice: 1, Octets: []byte("ABC")}, alias{Choice: 1, Octets: []byte("XYZ")}},
		{"outer-inner-octets", outer{Inner: pick{Choice: 1, Octets: []byte("ABC")}}, outer{Inner: pick{Choice: 1, Octets: []byte("XYZ")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := compareBERValue(reflect.ValueOf(tc.after), reflect.ValueOf(tc.before), 0); got != berValueDifferent {
				t.Fatalf("verdict = %v, want different", got)
			}
		})
	}
}

func TestBERReplayCompleteRequiresFirmNodeVerdicts(t *testing.T) {
	var comparisons replayNodeComparisons
	comparisons.put(1, berValueEqual)
	comparisons.put(2, berValueUnknown)
	if comparisons.complete(2) {
		t.Fatal("an unknown child cannot take the typed replay shortcut")
	}
	comparisons.put(2, berValueDifferent)
	if !comparisons.complete(2) {
		t.Fatal("two firm child verdicts should complete the comparison")
	}
	for node := uintptr(3); node <= uintptr(len(comparisons.inlineNodes)+1); node++ {
		comparisons.put(node, berValueEqual)
	}
	comparisons.put(uintptr(len(comparisons.inlineNodes)+1), berValueUnknown)
	if comparisons.complete(len(comparisons.inlineNodes) + 1) {
		t.Fatal("an unknown child in overflow cannot take the typed replay shortcut")
	}
}

func TestBERReplayKnownUnknownExtensionNameIsAlternative(t *testing.T) {
	type pick struct {
		Choice           int
		berReplayNode_   *ReplayNode
		UnknownExtension []byte
		Other            []byte
	}
	for _, tc := range []struct {
		name   string
		before pick
		after  pick
	}{
		{"first", pick{Choice: 1, UnknownExtension: []byte("ABC")}, pick{Choice: 1, UnknownExtension: []byte("XYZ")}},
		{"second", pick{Choice: 2, Other: []byte("ABC")}, pick{Choice: 2, Other: []byte("XYZ")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.before.berReplayNode_ = new(ReplayNode)
			tc.after.berReplayNode_ = tc.before.berReplayNode_
			if got := compareBERValue(reflect.ValueOf(tc.after), reflect.ValueOf(tc.before), 0); got != berValueDifferent {
				t.Fatalf("verdict = %v, want different", got)
			}
		})
	}
}
