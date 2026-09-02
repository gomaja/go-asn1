package runtime

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestBigIntValueJSONAndCloning(t *testing.T) {
	t.Parallel()

	const decimal = "922337203685477580812345678901234567890"
	original, _ := new(big.Int).SetString(decimal, 10)
	clone := CloneBigInt(original)
	original.SetInt64(1)
	if got := clone.String(); got != decimal {
		t.Fatalf("CloneBigInt() = %s after source mutation, want %s", got, decimal)
	}

	encoded, err := MarshalBigIntJSON(clone)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `"`+decimal+`"`; got != want {
		t.Fatalf("MarshalBigIntJSON() = %s, want %s", got, want)
	}
	for _, input := range [][]byte{encoded, []byte(decimal)} {
		decoded, err := UnmarshalBigIntJSON(input)
		if err != nil || decoded.Cmp(clone) != 0 {
			t.Fatalf("UnmarshalBigIntJSON(%s) = %v, %v", input, decoded, err)
		}
	}

	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	if generic != decimal {
		t.Fatalf("generic JSON value = %#v, want exact decimal string", generic)
	}
}

func TestParseBigIntDecimalRejectsNonCanonicalText(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "+1", "01", "-0", "1.0", "1e3", " 1"} {
		if _, err := ParseBigIntDecimal(input); err == nil {
			t.Fatalf("ParseBigIntDecimal(%q) succeeded", input)
		}
	}
	if got, err := ParseBigIntDecimal("-42"); err != nil || got.Int64() != -42 {
		t.Fatalf("ParseBigIntDecimal(-42) = %v, %v", got, err)
	}
}

func FuzzBigIntJSONRoundTrip(f *testing.F) {
	for _, seed := range []string{"0", "-1", "9007199254740992", "922337203685477580812345678901234567890", "01", "+1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		value, err := ParseBigIntDecimal(input)
		if err != nil {
			return
		}
		encoded, err := MarshalBigIntJSON(value)
		if err != nil {
			t.Fatalf("MarshalBigIntJSON(%q): %v", input, err)
		}
		decoded, err := UnmarshalBigIntJSON(encoded)
		if err != nil {
			t.Fatalf("UnmarshalBigIntJSON(%s): %v", encoded, err)
		}
		if decoded.Cmp(value) != 0 {
			t.Fatalf("round trip = %s, want %s", decoded, value)
		}
	})
}
