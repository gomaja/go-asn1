// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/encoder_test_helpers_test.go; SHA-256 ea4eafe10bf3e04233ec131db8b1458ce0d9f6daba7d8d1bfcde11b4665a6111.
package ber

import "testing"

func mustEncode(t *testing.T) func([]byte, error) []byte {
	t.Helper()
	return func(encoded []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatalf("BER encode: %v", err)
		}
		return encoded
	}
}
