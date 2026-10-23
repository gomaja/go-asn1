// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/guard_census_test.go; SHA-256 9b57f1bce79403c2eda9029bc808d2ca051a6ca92ef38aeb2e210e8981f237f5.
package runtime

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestCensusOIDValidationAndMethods(t *testing.T) {
	for _, wire := range []string{"\x80", "\x81"} {
		if _, err := ObjectIdentifierFromEncoded(wire); !errors.Is(err, ErrTruncatedOID) {
			t.Fatalf("unterminated %x: %v", wire, err)
		}
	}
	if _, err := ObjectIdentifierFromEncoded("\x80\x01"); !errors.Is(err, ErrInvalidOID) {
		t.Fatalf("nonminimal combined root: %v", err)
	}
	if _, err := ObjectIdentifierFromEncoded("\x2a\x80\x01"); !errors.Is(err, ErrInvalidOID) {
		t.Fatalf("nonminimal second arc: %v", err)
	}
	if _, err := ParseObjectIdentifier("9.1"); !errors.Is(err, ErrInvalidOID) {
		t.Fatalf("first arc: %v", err)
	}
	if arcs, ok := (ObjectIdentifier{}).Arcs(); ok || arcs != nil {
		t.Fatalf("absent arcs: %v %v", arcs, ok)
	}
	for _, marshal := range []func() ([]byte, error){(ObjectIdentifier{}).MarshalText, (ObjectIdentifier{}).MarshalJSON} {
		if _, err := marshal(); !errors.Is(err, ErrInvalidOID) {
			t.Fatalf("absent value: %v", err)
		}
	}
	want := MustObjectIdentifierFromArcs(2, math.MaxUint64)
	got, err := ParseObjectIdentifier("2.18446744073709551615")
	if err != nil || got != want {
		t.Fatalf("combined root overflow: %v %v", got, err)
	}
	if arcs, ok := got.Arcs(); !ok || len(arcs) != 2 || arcs[1] != math.MaxUint64 {
		t.Fatalf("split root: %v %v", arcs, ok)
	}
	got, err = ParseObjectIdentifier("2.18446744073709551616")
	if err != nil || got.String() != "2.18446744073709551616" {
		t.Fatalf("big arc: %v %v", got, err)
	}
	saved := MustObjectIdentifier("1.2")
	for _, input := range []string{"", "null", "123", "{}"} {
		got = saved
		if err := got.UnmarshalJSON([]byte(input)); !errors.Is(err, ErrInvalidOID) || got != saved {
			t.Fatalf("wrong JSON kind %q: %v", input, err)
		}
	}
	got = saved
	err = got.UnmarshalJSON([]byte(`"1.2\q"`))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) || got != saved {
		t.Fatalf("JSON syntax/transaction: %v", err)
	}
	if !((BitString{Bytes: []byte{0x80}, BitLength: 1}).Has(0)) {
		t.Fatal("first bit missing")
	}
	if got, err := ParseBigIntDecimal("123456789012345678901234567890"); err != nil || got.String() != "123456789012345678901234567890" {
		t.Fatalf("canonical integer: %v %v", got, err)
	}
}

func TestCensusRelativeOIDRefusals(t *testing.T) {
	for _, marshal := range []func() ([]byte, error){(RelativeObjectIdentifier{}).MarshalText, (RelativeObjectIdentifier{}).MarshalJSON} {
		if _, err := marshal(); !errors.Is(err, ErrInvalidOID) {
			t.Errorf("absent relative identifier: %v", err)
		}
	}
	if _, err := RelativeObjectIdentifierFromEncoded("\x80"); !errors.Is(err, ErrTruncatedOID) {
		t.Errorf("unterminated relative identifier: %v", err)
	}
	saved := MustRelativeObjectIdentifier("1.2")
	value := saved
	if err := value.UnmarshalText([]byte(strings.Repeat("1", MaxOIDTextLength+1))); !errors.Is(err, ErrOIDTextLimit) || value != saved {
		t.Errorf("overlong relative text: %v", err)
	}
	value = saved
	if err := value.UnmarshalJSON([]byte(strings.Repeat("1", MaxOIDJSONLength+1))); !errors.Is(err, ErrOIDTextLimit) || value != saved {
		t.Errorf("overlong relative JSON: %v", err)
	}
	for _, input := range []string{"", "null", "123", "{}"} {
		value = saved
		if err := value.UnmarshalJSON([]byte(input)); !errors.Is(err, ErrInvalidOID) || value != saved {
			t.Errorf("wrong relative JSON kind %q: %v", input, err)
		}
	}
	value = saved
	if err := value.UnmarshalJSON([]byte(`"1.2\q"`)); err == nil || value != saved {
		t.Errorf("malformed relative JSON: %v", err)
	}
	value = saved
	if err := value.UnmarshalText([]byte("3.4")); err != nil || value.String() != "3.4" {
		t.Errorf("valid relative text: %v, %s", err, value.String())
	}
	for _, construct := range []func(){
		func() { MustRelativeObjectIdentifier("a") },
		func() { MustRelativeObjectIdentifierFromArcs() },
		func() { MustRelativeObjectIdentifierFromEncoded("\x80") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid relative identifier constructor did not panic")
				}
			}()
			construct()
		}()
	}
}

func TestCensusOIDFormattingLimits(t *testing.T) {
	// Many machine-width arcs hit the aggregate limit on the fast formatting path.
	wire := appendOIDUint(nil, 42)
	for range 3300 {
		wire = appendOIDUint(wire, math.MaxUint64)
	}
	oid, err := ObjectIdentifierFromEncoded(string(wire))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = oid.StringChecked(); !errors.Is(err, ErrOIDTextLimit) {
		t.Fatalf("fast aggregate text limit: %v", err)
	}
	// A big first subidentifier forces the arbitrary-width formatter. Build an
	// exact permitted text boundary, then add a final wire arc beyond it.
	text := "2.18446744073709551616"
	for len(text)+1+MaxOIDArcDigits <= MaxOIDTextLength {
		text += "." + strings.Repeat("1", MaxOIDArcDigits)
	}
	if remaining := MaxOIDTextLength - len(text); remaining > 1 {
		text += "." + strings.Repeat("1", remaining-1)
	}
	if len(text) != MaxOIDTextLength {
		t.Fatalf("boundary length %d", len(text))
	}
	oid, err = ParseObjectIdentifier(text)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := oid.StringChecked(); err != nil || got != text {
		t.Fatalf("exact text boundary: length=%d %v", len(got), err)
	}
	var parsed ObjectIdentifier
	if err := parsed.UnmarshalText([]byte(text)); err != nil || parsed != oid {
		t.Fatalf("exact unmarshal boundary: %v", err)
	}
	oversized := ObjectIdentifier{enc: oid.enc + "\x01"}
	if _, err := oversized.StringChecked(); !errors.Is(err, ErrOIDTextLimit) {
		t.Fatalf("big aggregate text limit: %v", err)
	}
}

func TestCensusOIDSplitRootArcCountLimit(t *testing.T) {
	for _, extra := range []int{0, 1} {
		oid, err := ObjectIdentifierFromEncoded("\x2a" + strings.Repeat("\x01", MaxOIDArcs-2+extra))
		if err != nil {
			t.Fatal(err)
		}
		text, err := oid.StringChecked()
		if extra == 0 {
			if err != nil || strings.Count(text, ".") != MaxOIDArcs-1 {
				t.Fatalf("exact arc count: %v", err)
			}
		} else if !errors.Is(err, ErrOIDTextLimit) {
			t.Fatalf("root split arc omitted from bound: %v", err)
		}
	}
}
