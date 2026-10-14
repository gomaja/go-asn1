// Code generated from ASN.1. DO NOT EDIT.

// Codes retain information-object provenance (X.880 §§8.2.13, 8.3.5, 8.8).
package ros

import "fmt"

// ErrorCode is a local INTEGER code.
type ErrorCode int64

const (
	// Refuse identifies refuse. Source: x880-tc1-useful-definitions/modules/Remote-Operations-Useful-Definitions.asn; SHA-256 5c710fb2e552c81149924d29312b4abf00a94980b61cb0198869e0823d6c9e40.
	Refuse ErrorCode = -1
)

// String returns the first source name for this code.
func (c ErrorCode) String() string {
	switch c {
	case Refuse:
		return "refuse"
	default:
		return fmt.Sprintf("ErrorCode(%d)", int64(c))
	}
}

// OperationCode is a local INTEGER code.
type OperationCode int64

const (
	// NoOp identifies no-op. Source: x880-tc1-useful-definitions/modules/Remote-Operations-Useful-Definitions.asn; SHA-256 5c710fb2e552c81149924d29312b4abf00a94980b61cb0198869e0823d6c9e40.
	NoOp OperationCode = -1
)

// String returns the first source name for this code.
func (c OperationCode) String() string {
	switch c {
	case NoOp:
		return "no-op"
	default:
		return fmt.Sprintf("OperationCode(%d)", int64(c))
	}
}
