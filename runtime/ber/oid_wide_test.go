package ber

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUUIDOID(t *testing.T) {
	// X.667 (10/2012) §8 example; X.690 (02/2021) §8.19.
	wire, _ := hex.DecodeString("06146983f09da7ebcfdee0c7a1a7b2c0948cc8f9d776")
	oid, n, err := DecodeObjectIdentifier(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(wire) {
		t.Fatal(n)
	}
	got, err := EncodeObjectIdentifier(oid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("got %x want %x", got, wire)
	}
}
