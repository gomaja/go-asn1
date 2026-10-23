// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/integer_value_test.go; SHA-256 e22e5bfe5847e78eedeff23ac07d4b7f0bb27ed5503d88bfbc4dbe9035126a39.
package runtime

import (
	"testing"
)

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
