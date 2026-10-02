package ber

import "fmt"

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
