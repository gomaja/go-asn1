// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/constraints_example_test.go; SHA-256 790d81fd762c11d6d7422010d53accc26be36adc9bc4a37c9d42710d3fc2b01a.
package ber

import (
	"fmt"
)

func ExampleWithConstraintTolerance() {
	var violations ViolationLog
	option := WithConstraintTolerance(&violations)
	_ = CheckDecodedLength([]DecodeOption{option}, "field", "SIZE (1)", 2)
	for _, violation := range violations.Snapshot() {
		fmt.Printf("%s: %s, length %d\n", violation.Path, violation.Constraint, *violation.ObservedLength)
	}
	violations.Reset()
	fmt.Printf("remaining: %d\n", len(violations.Snapshot()))
	// Output:
	// field: SIZE (1), length 2
	// remaining: 0
}
