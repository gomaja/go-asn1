// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_compare.go; SHA-256 a003b00530648c46b630a579066d4fd1fd91a20a11d4c4622dbaf5703aa4f003.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"math/big"
	"reflect"
)

// CheckBERReplayComparatorsForTesting checks generated replay decisions against
// the reflection reference at decode completion and on subsequent comparisons.
// A disagreement panics; this option is solely a differential-test oracle.
func CheckBERReplayComparatorsForTesting() DecodeOption {
	return decodeOptionFunc(func(c *decodeConfig) error { c.checkReplayComparator = true; return nil })
}

// Record stores a generated node's verdict when its baseline has the same
// replay identity. Verdicts are 0 (unknown), 1 (equal), or 2 (different).
// An optional independent proof may retain an unknown source-owned subtree;
// the reference verdict itself remains unknown.
func (c *BERReplayComparisons) Record(node, baseline *ReplayNode, verdict int, proofs ...func() bool) {
	if c != nil && !c.proofOnly && node != nil && node == baseline {
		identity := reflect.ValueOf(node).Pointer()
		c.put(identity, berValueComparison(verdict))
		if c.allowProof && verdict == int(berValueUnknown) && len(proofs) != 0 && proofs[0] != nil && proofs[0]() {
			c.prove(identity)
		}
	}
}

// ProveEqual records a separate source-owned equality proof for the root.
// It does not replace the reference's three-way verdict or child decisions.
// The caller must compare every source value and OPTIONAL/DEFAULT presence.
func (c *BERReplayComparisons) ProveEqual(equal bool) {
	if c != nil {
		c.sourceEqual = equal
	}
}

// CompareBERReplayPrimitive supplies the primitive leaves of generated replay
// comparators. accessible preserves the reference comparator's uncertainty for
// private fields; it never grants an unproved replay shortcut.
// X.690 (02/2021) §§8.1.2, 8.6.2.2, 8.14, 8.18.1.
func CompareBERReplayPrimitive(left, right any, accessible bool) int {
	result := berValueUnknown
	switch a := left.(type) {
	case *big.Int:
		if b, ok := right.(*big.Int); ok && accessible {
			result = berComparison(a.Cmp(b) == 0)
		}
	case *runtime.ObjectIdentifier:
		if b, ok := right.(*runtime.ObjectIdentifier); ok && accessible {
			result = berComparison(*a == *b)
		}
	case *runtime.BitString:
		if b, ok := right.(*runtime.BitString); ok && accessible {
			result = compareReplayBits(*a, *b)
		}
	case *runtime.RawValue:
		if b, ok := right.(*runtime.RawValue); ok && accessible {
			result = compareReplayRaw(*a, *b)
		}
	case *runtime.External:
		if b, ok := right.(*runtime.External); ok {
			result = compareReplayExternal(a, b, accessible)
		}
	}
	return int(result)
}

func compareReplayRaw(a, b runtime.RawValue) berValueComparison {
	if a.Class == b.Class && a.Tag == b.Tag && a.Constructed == b.Constructed && bytes.Equal(a.Bytes, b.Bytes) {
		return berValueEqual
	}
	aTag, aLength, aErr := DecodeTag(a.Bytes)
	bTag, bLength, bErr := DecodeTag(b.Bytes)
	if aErr == nil && bErr == nil && (aTag.Constructed != bTag.Constructed || !bytes.Equal(a.Bytes[aLength:], b.Bytes[bLength:])) {
		return berValueDifferent
	}
	return berValueUnknown
}

func compareReplayBits(a, b runtime.BitString) berValueComparison {
	if !berBitStringLengthFits(a) || !berBitStringLengthFits(b) || a.BitLength != b.BitLength {
		return berValueUnknown
	}
	full := a.BitLength / 8
	if !bytes.Equal(a.Bytes[:full], b.Bytes[:full]) {
		return berValueDifferent
	}
	if rem := a.BitLength % 8; rem != 0 {
		mask := ^byte(0) << (8 - rem)
		if a.Bytes[full]&mask != b.Bytes[full]&mask {
			return berValueDifferent
		}
	}
	if bytes.Equal(a.Bytes, b.Bytes) {
		return berValueEqual
	}
	return berValueUnknown
}

func compareReplayExternal(a, b *runtime.External, accessible bool) berValueComparison {
	if !accessible {
		// Reflection cannot project private EXTERNAL fields into the selected
		// alternative comparator. Its generic walk can prove these exported
		// scalar and octet fields different, but cannot prove the value equal.
		if a.Encoding != b.Encoding || !bytes.Equal(a.OctetAligned, b.OctetAligned) ||
			a.DataValueDescriptor != nil && b.DataValueDescriptor != nil && a.DataValueDescriptor != b.DataValueDescriptor && *a.DataValueDescriptor != *b.DataValueDescriptor {
			return berValueDifferent
		}
		return berValueUnknown
	}
	if a.Encoding != b.Encoding || a.DirectReference != b.DirectReference {
		return berValueDifferent
	}
	if (a.IndirectReference == nil) != (b.IndirectReference == nil) || (a.DataValueDescriptor == nil) != (b.DataValueDescriptor == nil) {
		return berValueUnknown
	}
	if a.IndirectReference != nil && a.IndirectReference.Cmp(b.IndirectReference) != 0 || a.DataValueDescriptor != nil && *a.DataValueDescriptor != *b.DataValueDescriptor {
		return berValueDifferent
	}
	switch a.Encoding {
	case runtime.ExternalSingleASN1Type:
		if a.SingleASN1Type.Class == b.SingleASN1Type.Class && a.SingleASN1Type.Tag == b.SingleASN1Type.Tag && a.SingleASN1Type.Constructed == b.SingleASN1Type.Constructed && bytes.Equal(a.SingleASN1Type.Bytes, b.SingleASN1Type.Bytes) {
			return berValueEqual
		}
		return berValueUnknown
	case runtime.ExternalOctetAligned:
		return berComparison(bytes.Equal(a.OctetAligned, b.OctetAligned))
	case runtime.ExternalArbitrary:
		return compareReplayBits(a.Arbitrary, b.Arbitrary)
	default:
		return berValueUnknown
	}
}

// CheckBERReplayComparatorForTesting compares generated verdicts and every
// recorded descendant with the reflection reference. It never encodes a value.
func CheckBERReplayComparatorForTesting(left, right any, generated func(*BERReplayComparisons) int) error {
	var actual, reference BERReplayComparisons
	got := berValueComparison(generated(&actual))
	want := compareBERValueNodes(reflect.ValueOf(left), reflect.ValueOf(right), 0, &reference)
	if got != want {
		return fmt.Errorf("BER replay verdict: generated %d, reference %d", got, want)
	}
	if actual.count+len(actual.overflow) != reference.count+len(reference.overflow) {
		return fmt.Errorf("BER replay node count: generated %d, reference %d", actual.count+len(actual.overflow), reference.count+len(reference.overflow))
	}
	for i := 0; i < reference.count; i++ {
		if result, ok := actual.get(reference.inlineNodes[i]); !ok || result != reference.inlineResults[i] {
			return fmt.Errorf("BER replay descendant verdict differs")
		}
	}
	for node, want := range reference.overflow {
		if result, ok := actual.get(node); !ok || result != want {
			return fmt.Errorf("BER replay descendant verdict differs")
		}
	}
	return nil
}
