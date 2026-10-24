// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/strict_regression_test.go; SHA-256 2c230d778c7a133ac291a6bb44f09ef2145beb59ae8e878c1dd68b138a01c417.
package aper

import "testing"

// X.691 (02/2021) §11.1.4 requires zero terminal bits at both complete
// boundaries; §11.2.1 applies that rule inside a known open value.
func TestStrictTerminalPaddingRegression(t *testing.T) {
	for _, capture := range []struct {
		name string
		run  func(*BitBuffer) (CompletePadding, error)
	}{{"top", CaptureFinalPadding}, {"open", CaptureOpenTypePadding}} {
		t.Run(capture.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{1})
			if _, err := bb.ReadBits(3); err != nil {
				t.Fatal(err)
			}
			if _, err := capture.run(bb); err == nil {
				t.Fatal("nonzero complete padding accepted")
			}
		})
	}
}
