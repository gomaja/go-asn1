// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/interfaces_test.go; SHA-256 10e70ff22a7ba270b072043b8b9e82533df62b9838a7290ba32177700352f5eb.
package runtime

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOwnedValueInterfacesAndConstructors(t *testing.T) {
	const dotted = "1.3.6.1.4.1.55555.7"
	value := MustObjectIdentifier(dotted)
	fromArcs := MustObjectIdentifierFromArcs(1, 3, 6, 1, 4, 1, 55555, 7)
	fromWire := MustObjectIdentifierFromEncoded(value.Encoded())
	if !value.Equal(fromArcs) || !value.Equal(fromWire) || value.IsZero() {
		t.Fatal("immutable constructors differ")
	}
	if arcs, ok := value.Arcs(); !ok || !reflect.DeepEqual(arcs, []uint64{1, 3, 6, 1, 4, 1, 55555, 7}) {
		t.Fatalf("arcs = %v, %v", arcs, ok)
	}
	contents := value.Bytes()
	if string(contents) != value.Encoded() {
		t.Fatal("Bytes changed OID contents")
	}
	contents[0] ^= 0xff
	if value.Encoded() != fromWire.Encoded() || string(value.Bytes()) != value.Encoded() {
		t.Fatal("Bytes exposed immutable OID storage")
	}
	if len((ObjectIdentifier{}).Bytes()) != 0 {
		t.Fatal("zero OID has contents")
	}
	text, err := value.MarshalText()
	if err != nil || string(text) != dotted {
		t.Fatalf("text = %q, %v", text, err)
	}
	var decoded ObjectIdentifier
	if err := decoded.UnmarshalText(text); err != nil || !decoded.Equal(value) {
		t.Fatalf("text round trip = %v, %v", decoded, err)
	}
	document, err := json.Marshal(value)
	if err != nil || string(document) != `"1.3.6.1.4.1.55555.7"` {
		t.Fatalf("JSON = %s, %v", document, err)
	}
	if err := json.Unmarshal(document, &decoded); err != nil || !decoded.Equal(value) {
		t.Fatalf("JSON round trip = %v, %v", decoded, err)
	}
	if err := json.Unmarshal([]byte(`"1.03.6"`), &decoded); err == nil || !decoded.Equal(value) {
		t.Fatalf("failed JSON changed receiver: %v, %v", decoded, err)
	}
	if got := MustParseBigIntDecimal("18446744073709551616").String(); got != "18446744073709551616" {
		t.Fatal(got)
	}
}
