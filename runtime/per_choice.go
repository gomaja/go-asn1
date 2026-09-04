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
