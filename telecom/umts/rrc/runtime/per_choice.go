// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/per_choice.go; SHA-256 66d036e3cfdfd37de0cd7ae9e8db14f0e540ec4cb7738dddd025c5ad328ff889.
package runtime

// PERChoiceExtension preserves an extension alternative that is unknown to
// the compiled schema. Index is relative to the CHOICE extension root under
// ITU-T X.691 (02/2021), clauses 23.2 and 23.8. Payload is the octet string
// produced by the complete encoding in clauses 11.1 and 11.2.1; the enclosing
// length and fragmentation from clauses 11.2.2 and 11.9 are not retained.
type PERChoiceExtension struct {
	Index   int64  `json:"index"`
	Payload []byte `json:"payload"`
}
