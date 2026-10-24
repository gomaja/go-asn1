// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	hex "encoding/hex"
	testing "testing"
)

func asn1VectorHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
