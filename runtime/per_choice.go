package runtime

// PERChoiceExtension preserves an extension alternative that is unknown to
// the compiled schema. Index is relative to the CHOICE extension root and
// Payload is the complete open-type contents in transmission order, as
// specified by ITU-T X.691 (02/2021), clauses 23.8 and 11.9.
type PERChoiceExtension struct {
	Index   int64  `json:"index"`
	Payload []byte `json:"payload"`
}
