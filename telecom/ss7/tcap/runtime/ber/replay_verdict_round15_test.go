// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_verdict_round15_test.go; SHA-256 e7d81c09c30ba2ca8460d47d32ef1227d5bb4bdd7f8ae7b6fa36edf23dd00e34.
package ber

import (
	"testing"
)

func TestBERReplayCompleteRequiresFirmNodeVerdicts(t *testing.T) {
	var comparisons BERReplayComparisons
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
