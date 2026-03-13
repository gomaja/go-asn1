// Package constraint provides ASN.1 constraint representations.
package constraint

// ValueRange represents a value constraint with optional extensibility.
type ValueRange struct {
	Min        *int64
	Max        *int64
	Extensible bool
}

// SizeRange represents a size constraint with optional extensibility.
type SizeRange struct {
	Min        int64
	Max        int64
	Extensible bool
}

// PermittedAlphabet represents a FROM constraint on character strings.
type PermittedAlphabet struct {
	Chars      string
	Extensible bool
}
