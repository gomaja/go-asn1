// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/value_guards_test.go; SHA-256 0c7d2b5bc4cfa33bcddb375f192b141e2aa98767a1a323e6fee8dcb852150eb2.
package runtime

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRawValueJSONGuards(t *testing.T) {
	value := RawValue{Bytes: []byte{0xa5}}
	wire, err := json.Marshal(value)
	if err != nil || string(wire) != "\"a5\"" {
		t.Fatalf("%s %v", wire, err)
	}
	for _, bad := range []string{"null", "\"a\"", "\"gg\"", "5"} {
		before := append([]byte(nil), value.Bytes...)
		if err := value.UnmarshalJSON([]byte(bad)); err == nil || !bytes.Equal(value.Bytes, before) {
			t.Fatalf("invalid %s: %x %v", bad, value.Bytes, err)
		}
	}
	if err := value.UnmarshalJSON([]byte("\"\"")); err != nil || value.Bytes == nil || len(value.Bytes) != 0 {
		t.Fatalf("present empty: %v %v", value.Bytes, err)
	}
}

func TestBitStringDeclaredLengthGuard(t *testing.T) {
	value := BitString{Bytes: []byte{0, 0x80}, BitLength: 8}
	if value.Has(8) {
		t.Fatal("bit beyond declared length was read")
	}
}

func TestOIDConstructionGuards(t *testing.T) {
	for _, text := range []string{"", "1", "3.0", "1.40", "2.01", "2.-1", "2. 1"} {
		if _, err := ParseObjectIdentifier(text); err == nil {
			t.Fatalf("invalid OID %q accepted", text)
		}
	}
	for _, arcs := range [][]uint64{nil, {1}, {3, 0}, {1, 40}} {
		if _, err := ObjectIdentifierFromArcs(arcs...); err == nil {
			t.Fatalf("invalid OID arcs %v accepted", arcs)
		}
	}
}
