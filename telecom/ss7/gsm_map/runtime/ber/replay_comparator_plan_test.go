// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_comparator_plan_test.go; SHA-256 a08a7286f8cc2bb6ed645bab2295a8fefbd4fdc5a91f13de15a79901523416ad.
package ber

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

type comparatorChoice struct {
	Choice           int
	berReplayNode_   *ReplayNode `asn1:"-"`
	Octets           []byte
	Child            *comparatorChild
	UnknownExtension []byte
}

type comparatorChild struct {
	Number         int
	Optional       []byte `asn1:"optional"`
	Raw            *runtime.RawValue
	berReplayNode_ *ReplayNode `asn1:"-"`
}

type comparatorRoot struct {
	Selected       comparatorChoice
	Children       []comparatorChild
	ExtData_       [][]byte    `asn1:"-"`
	ExtPresent_    bool        `asn1:"-"`
	berReplayNode_ *ReplayNode `asn1:"-"`
}

// A change in the comparison algorithm must preserve both the root verdict
// and every replay-node verdict. These shapes exercise the same tagged fields,
// CHOICE layout, open values and collection edits as generated TCAP, GSM MAP
// and structural replay values.
func TestBERComparatorPlanMatchesReference(t *testing.T) {
	random := rand.New(rand.NewSource(13918))
	for index := range 6000 {
		rootNode, choiceNode, childNode := new(ReplayNode), new(ReplayNode), new(ReplayNode)
		base := comparatorRoot{
			Selected:       comparatorChoice{Choice: 1, berReplayNode_: choiceNode, Octets: []byte{byte(index), 2}},
			Children:       []comparatorChild{{Number: index % 127, Optional: []byte{1}, Raw: &runtime.RawValue{Class: 0, Tag: 4, Bytes: []byte{4, 1, 1}}, berReplayNode_: childNode}},
			berReplayNode_: rootNode,
		}
		current := base
		current.Selected.Octets = append([]byte(nil), base.Selected.Octets...)
		current.Children = append([]comparatorChild(nil), base.Children...)
		current.Children[0].Optional = append([]byte(nil), base.Children[0].Optional...)
		switch random.Intn(12) {
		case 0:
			current.Selected.Octets[0]++
		case 1:
			current.Selected.Choice = 2
			current.Selected.Child = &comparatorChild{Number: 3}
		case 2:
			current.Selected.UnknownExtension = []byte{4}
		case 3:
			current.Children[0].Number++
		case 4:
			current.Children[0].Optional = nil
		case 5:
			current.Children[0].Optional = []byte{}
		case 6:
			current.Children[0].Raw = &runtime.RawValue{Class: 0, Tag: 4, Bytes: []byte{4, 1, 2}}
		case 7:
			current.ExtData_ = [][]byte{{0x80, 1, 2}}
		case 8:
			current.ExtPresent_ = true
		case 9:
			current.Children = append(current.Children, comparatorChild{Number: 4})
		case 10:
			current.Selected.Choice = 3
			current.Selected.UnknownExtension = []byte{3}
		case 11:
			current.Children[0].berReplayNode_ = new(ReplayNode)
		}
		var oldNodes, newNodes BERReplayComparisons
		oldResult := compareBERValueNodesReference(reflect.ValueOf(&current), reflect.ValueOf(&base), 0, &oldNodes)
		newResult := compareBERValueNodes(reflect.ValueOf(&current), reflect.ValueOf(&base), 0, &newNodes)
		if oldResult != newResult || !reflect.DeepEqual(oldNodes, newNodes) {
			t.Fatalf("case %d: result %v vs %v, node verdicts %#v vs %#v", index, oldResult, newResult, oldNodes, newNodes)
		}
	}
}

func BenchmarkBERComparator(b *testing.B) {
	node := new(ReplayNode)
	value := comparatorRoot{
		Selected:       comparatorChoice{Choice: 2, Child: &comparatorChild{Number: 7, Optional: []byte{1, 2, 3}, berReplayNode_: node}},
		Children:       []comparatorChild{{Number: 4, Optional: []byte{1}, berReplayNode_: node}},
		ExtData_:       [][]byte{{0x80, 1, 7}},
		berReplayNode_: node,
	}
	baseline := value
	baseline.Children = append([]comparatorChild(nil), value.Children...)
	baseline.Children[0].Number++
	for _, tc := range []struct {
		name string
		fn   func(reflect.Value, reflect.Value, int, *BERReplayComparisons) berValueComparison
	}{
		{"reference", compareBERValueNodesReference},
		{"planned", compareBERValueNodes},
	} {
		b.Run(tc.name, func(b *testing.B) {
			left, right := reflect.ValueOf(&value), reflect.ValueOf(&baseline)
			b.ReportAllocs()
			for b.Loop() {
				var nodes BERReplayComparisons
				if tc.fn(left, right, 0, &nodes) != berValueDifferent {
					b.Fatal("lost value change")
				}
			}
		})
	}
}

type comparatorContainers struct {
	Changed        int
	InInterface    any
	InMap          map[int]comparatorChild
	InArray        [1]comparatorChild
	berReplayNode_ *ReplayNode `asn1:"-"`
}

func TestBERComparatorPlanKeepsNestedNodeVerdictsAfterDifference(t *testing.T) {
	rootNode, interfaceNode, mapNode, arrayNode := new(ReplayNode), new(ReplayNode), new(ReplayNode), new(ReplayNode)
	baseline := comparatorContainers{
		InInterface:    comparatorChild{Number: 1, berReplayNode_: interfaceNode},
		InMap:          map[int]comparatorChild{0: {Number: 2, berReplayNode_: mapNode}},
		InArray:        [1]comparatorChild{{Number: 3, berReplayNode_: arrayNode}},
		berReplayNode_: rootNode,
	}
	current := baseline
	current.Changed = 1
	for name, edit := range map[string]func(*comparatorContainers){
		"unchanged": func(*comparatorContainers) {},
		"interface": func(c *comparatorContainers) {
			c.InInterface = comparatorChild{Number: 4, berReplayNode_: interfaceNode}
		},
		"map": func(c *comparatorContainers) {
			c.InMap = map[int]comparatorChild{0: {Number: 5, berReplayNode_: mapNode}}
		},
		"array": func(c *comparatorContainers) { c.InArray[0].Number = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			value := current
			edit(&value)
			var oldNodes, newNodes BERReplayComparisons
			oldResult := compareBERValueNodesReference(reflect.ValueOf(&value), reflect.ValueOf(&baseline), 0, &oldNodes)
			newResult := compareBERValueNodes(reflect.ValueOf(&value), reflect.ValueOf(&baseline), 0, &newNodes)
			if oldResult != newResult || !reflect.DeepEqual(oldNodes, newNodes) {
				t.Fatalf("verdicts differ: root %v vs %v, nodes %#v vs %#v", oldResult, newResult, oldNodes, newNodes)
			}
		})
	}
}

type comparatorNamedBytes []byte

type comparatorNamedHolder struct {
	Required       comparatorNamedBytes
	Optional       comparatorNamedBytes `asn1:"optional"`
	berReplayNode_ *ReplayNode          `asn1:"-"`
}

type comparatorExtensibleChoice struct {
	Choice           int
	berReplayNode_   *ReplayNode `asn1:"-"`
	UnknownExtension *runtime.BERChoiceExtension
	Octets           []byte
	Child            *comparatorChild
}

func TestBERComparatorPlanMatchesChoiceExtensions(t *testing.T) {
	node := new(ReplayNode)
	base := comparatorExtensibleChoice{Choice: 1, berReplayNode_: node, Octets: []byte("ABC")}
	withExtension := base
	withExtension.UnknownExtension = &runtime.BERChoiceExtension{Element: []byte{0x82, 1, 7}}
	for _, tc := range []struct {
		name     string
		baseline comparatorExtensibleChoice
		current  comparatorExtensibleChoice
	}{
		{"unchanged", base, base},
		{"known-edit", base, comparatorExtensibleChoice{Choice: 1, berReplayNode_: node, Octets: []byte("XYZ")}},
		{"selected-edit", base, comparatorExtensibleChoice{Choice: 2, berReplayNode_: node, Child: &comparatorChild{Number: 7}}},
		{"both-selected", base, withExtension},
		{"extension-removed", withExtension, base},
		{"unknown-choice", base, comparatorExtensibleChoice{Choice: 0, berReplayNode_: node, UnknownExtension: &runtime.BERChoiceExtension{Element: []byte{0x82, 1, 7}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var referenceNodes, plannedNodes BERReplayComparisons
			reference := compareBERValueNodesReference(reflect.ValueOf(tc.current), reflect.ValueOf(tc.baseline), 0, &referenceNodes)
			planned := compareBERValueNodes(reflect.ValueOf(tc.current), reflect.ValueOf(tc.baseline), 0, &plannedNodes)
			if planned != reference || !reflect.DeepEqual(plannedNodes, referenceNodes) {
				t.Fatalf("verdicts differ: root %v vs %v, nodes %#v vs %#v", planned, reference, plannedNodes, referenceNodes)
			}
		})
	}
}

func TestBERComparatorPlanMatchesNamedByteSlices(t *testing.T) {
	node := new(ReplayNode)
	baseline := comparatorNamedHolder{Required: comparatorNamedBytes{1, 2}, berReplayNode_: node}
	for _, current := range []comparatorNamedHolder{
		baseline,
		{Required: comparatorNamedBytes{}, berReplayNode_: node},
		{Required: comparatorNamedBytes{1, 3}, berReplayNode_: node},
		{Required: comparatorNamedBytes{1, 2}, Optional: comparatorNamedBytes{}, berReplayNode_: node},
		{Required: comparatorNamedBytes{1, 2}, Optional: comparatorNamedBytes{3}, berReplayNode_: node},
	} {
		var oldNodes, newNodes BERReplayComparisons
		oldResult := compareBERValueNodesReference(reflect.ValueOf(&current), reflect.ValueOf(&baseline), 0, &oldNodes)
		newResult := compareBERValueNodes(reflect.ValueOf(&current), reflect.ValueOf(&baseline), 0, &newNodes)
		if oldResult != newResult || !reflect.DeepEqual(oldNodes, newNodes) {
			t.Fatalf("named byte slice verdicts differ: root %v vs %v, nodes %#v vs %#v", oldResult, newResult, oldNodes, newNodes)
		}
	}
}
