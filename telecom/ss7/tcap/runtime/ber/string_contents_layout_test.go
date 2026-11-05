// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/string_contents_layout_test.go; SHA-256 98ab61e93eeb91053df6dfb5137d999b0e59da5995348ec7f7ec33115918c56c.
package ber

import (
	"testing"
	"unsafe"
)

func TestStringContentsLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout")
	}
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"scan frame", unsafe.Sizeof(berScanFrame{}), 120},
		{"form state", unsafe.Sizeof(berFormState{}), 120},
		{"decode configuration", unsafe.Sizeof(decodeConfig{}), 168},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, published layout %d", c.name, c.got, c.want)
		}
	}
}
