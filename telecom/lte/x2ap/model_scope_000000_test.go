// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	hex "encoding/hex"
	testing "testing"
)

func asn1ContractHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
