// Code generated from ASN.1. DO NOT EDIT.

package gsm_map

// BERValue holds a typed standalone ASN.1 value and private replay metadata.
// Construct a fresh value with BERValue[T]{Value: v}. Only a generated decoder
// records received bytes; editing Value invalidates replay on the next encode.
// X.690 (02/2021) §§8.1.3, 8.7.3 permit multiple BER forms for the same value.
type BERValue[T any] struct {
	Value        T
	berOriginal_ []byte
	berSnapshot_ []byte
}
