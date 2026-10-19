// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/oid_checked_test.go; SHA-256 02e0df136c4a285d826b49e725b28d19bd541864cb4de300ac140d5780c28fcc.
package ber

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestEncodeOIDValueCheckedValidatesRootArcs(t *testing.T) {
	for _, test := range []struct {
		arcs []uint64
		want []byte
	}{
		{[]uint64{0, 0}, []byte{0}}, {[]uint64{1, 39}, []byte{0x4f}}, {[]uint64{2, 999, 3}, []byte{0x88, 0x37, 3}},
		{[]uint64{2, math.MaxUint64}, []byte{0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x4f}},
	} {
		oid, err := runtime.ObjectIdentifierFromArcs(test.arcs...)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeOIDValueChecked(oid)
		if err != nil || !bytes.Equal(encoded, test.want) {
			t.Fatalf("%v: %x %v", test.arcs, encoded, err)
		}
		decoded, err := DecodeOIDValue(encoded)
		if err != nil {
			t.Fatal(err)
		}
		arcs, ok := decoded.Arcs()
		if !ok || !reflect.DeepEqual(arcs, test.arcs) {
			t.Fatalf("%v %v", arcs, ok)
		}
	}
	for _, arcs := range [][]uint64{nil, {1}, {3, 0}, {0, 40}, {1, 40}} {
		if _, err := runtime.ObjectIdentifierFromArcs(arcs...); err == nil {
			t.Fatalf("accepted %v", arcs)
		}
	}
	if _, err := EncodeOIDValueChecked(runtime.ObjectIdentifier{}); err == nil {
		t.Fatal("accepted zero")
	}
	if EncodeOIDValue(runtime.ObjectIdentifier{}) != nil {
		t.Fatal("accepted zero")
	}
}
func TestRelativeOIDUsesEveryArcAsASubidentifier(t *testing.T) {
	oid := runtime.MustRelativeObjectIdentifierFromArcs(8571, 3, 2)
	encoded, err := EncodeRelativeOIDValueChecked(oid)
	if err != nil || !bytes.Equal(encoded, []byte{0xc2, 0x7b, 3, 2}) {
		t.Fatalf("%x %v", encoded, err)
	}
	decoded, err := DecodeRelativeOIDValue(encoded)
	if err != nil || decoded != oid {
		t.Fatalf("%v %v", decoded, err)
	}
	if _, err := EncodeRelativeOIDValueChecked(runtime.RelativeObjectIdentifier{}); err == nil {
		t.Fatal("accepted zero")
	}
}
func TestOIDDecoderRejectsNonCanonicalSubidentifiers(t *testing.T) {
	for _, value := range [][]byte{nil, {0x80, 0}, {0x2a, 0x80, 0}, {0x81}, {0x2a, 0x81}} {
		if decoded, err := DecodeOIDValue(value); err == nil || !decoded.IsZero() {
			t.Fatalf("accepted %x", value)
		}
		if decoded, err := DecodeRelativeOIDValue(value); err == nil || !decoded.IsZero() {
			t.Fatalf("accepted relative %x", value)
		}
	}
}
func TestOIDDecoderClassifiesLoneContinuationAsTruncated(t *testing.T) {
	if _, err := DecodeOIDValue([]byte{0x2a, 0x80}); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
}
