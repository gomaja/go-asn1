package runtime

// BERChoiceExtension preserves an extension alternative unknown to the
// compiled schema. Element contains the complete received BER element:
// identifier, length, contents and, for indefinite length, end-of-contents
// octets. ITU-T X.680 (02/2021) §§29.1, 52.2; X.690 (02/2021) §§8.1.1, 8.13.
type BERChoiceExtension struct {
	Element []byte `json:"element"`
}
