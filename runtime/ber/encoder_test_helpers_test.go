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
