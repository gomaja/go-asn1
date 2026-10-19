// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/rules_test.go; SHA-256 c6b08b82df7059f45c27cbec098384b2e02851b1d29f7b8afc71c2ed16c83815.
package ber

import (
	"errors"
	"reflect"
	"testing"
)

func TestGeneratedRuleIdentity(t *testing.T) {
	rule := RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}
	options := LocateDecodedElement([]byte{0x30, 3, 4, 1, 'x'}, "Module.Type", TrackBERForm(nil))
	MarkPreflightTarget(options, "field", []byte{4, 1, 'x'})
	// Mark from the original input so offset and physical child ancestry agree.
	config, err := decodeOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	MarkPreflightTarget(options, "field", config.location.input[2:])
	options = DecodeRule(options, "Module.Type", rule)
	err = CheckDecodedLength(options, "field", "SIZE (2)", 1)
	var failure *ValidationError
	if !errors.As(err, &failure) || failure.Rule != rule || failure.Source != "Module.Type.field" || failure.Offset == nil || *failure.Offset != 2 || !reflect.DeepEqual(failure.ChildIndexes, []int{0}) {
		t.Fatalf("generated rule/location=%+v: %v", failure, err)
	}
	fresh := CheckEncodedLength(EncodeRule(nil, "Module.Type", rule), "field", "SIZE (2)", 1)
	if !errors.As(fresh, &failure) || failure.Offset != nil || failure.Rule != rule || failure.Source != "Module.Type.field" {
		t.Fatalf("fresh source=%+v: %v", failure, fresh)
	}
	// Foreign diagnostic text must never activate TCAP rules in MAP's runtime.
	failure = nil
	err = CheckDecodedValue(nil, "field", "Q.773 §4.2.2.2", "128")
	if !errors.As(err, &failure) || failure.Kind != ASN1Constraint || failure.Rule.Document != "ITU-T X.680" {
		t.Fatalf("text selected protocol policy: %v", err)
	}
}
