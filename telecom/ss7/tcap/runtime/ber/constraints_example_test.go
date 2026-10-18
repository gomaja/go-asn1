// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/constraints_example_test.go; SHA-256 803200ad5d767d5d1907900bafc0222dc9bf769e5c44ae8c4a6bf9188ea90cf7.
package ber

import (
	"fmt"
)

func ExampleWithTolerance() {
	var violations ViolationLog
	option := WithTolerance(&violations)
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
