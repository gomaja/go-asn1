// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/oid_test.go; SHA-256 233e832aa57f32d6c1d492d13b0b662f925800ee33932fd4c10aace458206e00.
package runtime_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"strings"
	"testing"
)

func TestOIDDecodeLinearAllocationBound(t *testing.T) {
	for _, size := range []int{128, 1024, 8192, 65536} {
		wire, err := ber.EncodeObjectIdentifier(runtime.MustObjectIdentifierFromEncoded("\x81" + strings.Repeat("\x80", size-2) + "\x00"))
		if err != nil {
			t.Fatal(err)
		}
		var got runtime.ObjectIdentifier
		operation := func() {
			var e error
			got, _, e = ber.DecodeObjectIdentifier(wire)
			if e != nil {
				t.Fatal(e)
			}
		}
		allocated, allocations := allocationCost(t, 5, operation)
		// Repeated scans can be quadratic without allocating more memory.
		elapsed := minimumTime(t, operation)
		if len(got.Encoded()) != size || int64(allocated) > int64(size*2+256) || int64(allocations) > 2 || elapsed.Nanoseconds() > int64(size)*100 {
			t.Fatalf("size=%d time=%s bytes=%d allocs=%d", size, elapsed, allocated, allocations)
		}
		t.Logf("size=%d time=%s bytes=%d allocs=%d", size, elapsed, allocated, allocations)
	}
}

func FuzzOIDContents(f *testing.F) {
	for _, seed := range [][]byte{nil, {0x2a}, {0x80, 0}, {0x2a, 0x81}, {0x2a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > 4096 {
			t.Skip()
		}
		v, err := runtime.ObjectIdentifierFromEncoded(string(contents))
		if err != nil {
			return
		}
		if !bytes.Equal(v.Bytes(), contents) {
			t.Fatal("changed contents")
		}
		text, textErr := v.StringChecked()
		if textErr == nil {
			reparsed, err := runtime.ParseObjectIdentifier(text)
			if err != nil || reparsed != v {
				t.Fatalf("text roundtrip %x %v", contents, err)
			}
		} else if !errors.Is(textErr, runtime.ErrOIDTextLimit) {
			t.Fatal(textErr)
		}
		wire, err := ber.EncodeObjectIdentifier(v)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := ber.DecodeObjectIdentifier(wire)
		if err != nil || n != len(wire) || got != v {
			t.Fatal("BER roundtrip", err)
		}
	})
}

func TestExternalJSONOmitsAbsentIdentifier(t *testing.T) {
	v := runtime.External{Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{1, 2, 3}}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got runtime.External
	if err := json.Unmarshal(data, &got); err != nil || !got.DirectReference.IsZero() {
		t.Fatal(got, err)
	}
	if bytes.Contains(data, []byte("DirectReference")) {
		t.Fatal("absent reference emitted", string(data))
	}
	v.DirectReference = runtime.MustObjectIdentifier("2.25.329800735698586629295641978511506172918")
	data, err = json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil || got.DirectReference != v.DirectReference {
		t.Fatal("lost direct reference", err)
	}
}
