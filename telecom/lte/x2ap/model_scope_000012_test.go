// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	hex "encoding/hex"
)

func asn1VectorHexForFuzz(input string) []byte {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return decoded
}
