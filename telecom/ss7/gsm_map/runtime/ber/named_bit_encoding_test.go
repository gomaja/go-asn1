// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/named_bit_encoding_test.go; SHA-256 6b88ae496778caa93db87531b710a4807456ecf4283e5629fce228287727b095.
package ber

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

func TestNamedBitEncodingIntersection(t *testing.T) {
	tests := []struct {
		name        string
		significant int
		sets        []NamedBitSizeSet
		want        int
		invalid     bool
	}{
		{name: "unconstrained", significant: 1, want: 1},
		{name: "lower bound", significant: 1, sets: []NamedBitSizeSet{{{Min: 3, Max: 8}}}, want: 3},
		{name: "zero", sets: []NamedBitSizeSet{{{Min: 3, Max: 8}}}, want: 3},
		{name: "trailing zeros exceed upper bound", significant: 1, sets: []NamedBitSizeSet{{{Min: 3, Max: 8}}}, want: 3},
		{name: "disjoint", significant: 4, sets: []NamedBitSizeSet{{{Min: 3, Max: 3}, {Min: 8, Max: 8}}}, want: 8},
		{name: "intersection", significant: 4, sets: []NamedBitSizeSet{{{Min: 3, Max: 3}, {Min: 8, Max: 8}}, {{Min: 5, Max: 9}}}, want: 8},
		{name: "crossed alternatives", significant: 4, sets: []NamedBitSizeSet{{{Min: 4, Max: 5}, {Min: 10, Max: 12}}, {{Min: 6, Max: 11}}}, want: 10},
		{name: "empty intersection", sets: []NamedBitSizeSet{{{Min: 3, Max: 3}}, {{Min: 8, Max: 8}}}, invalid: true},
		{name: "empty set", sets: []NamedBitSizeSet{{}}, invalid: true},
		{name: "significant bit exceeds maximum", significant: 9, sets: []NamedBitSizeSet{{{Min: 3, Max: 8}}}, invalid: true},
		{name: "invalid range after match", significant: 3, sets: []NamedBitSizeSet{{{Min: 3, Max: 8}, {Min: 9, Max: 8}}}, invalid: true},
		{name: "host maximum minimum", sets: []NamedBitSizeSet{{{Min: math.MaxInt, Max: -1}}}, want: math.MaxInt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := namedBitEncodingLength(tc.significant, tc.sets)
			if tc.invalid {
				if !errors.Is(err, ErrInvalidValue) {
					t.Fatalf("got %d, %v", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestNormalizeNamedBitEncodingStorageAndOwnership(t *testing.T) {
	sets := []NamedBitSizeSet{{{Min: 3, Max: 8}}}
	for _, tc := range []struct {
		name  string
		value runtime.BitString
		want  []byte
	}{
		{"short", runtime.BitString{Bytes: []byte{0x80}, BitLength: 1}, []byte{0x80}},
		{"long", runtime.BitString{Bytes: []byte{0x80, 0}, BitLength: 16}, []byte{0x80}},
		{"unused dirty input", runtime.BitString{Bytes: []byte{0x81}, BitLength: 1}, []byte{0x80}},
		{"zero", runtime.BitString{}, []byte{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte(nil), tc.value.Bytes...)
			got, err := NormalizeNamedBitStringForEncoding(tc.value, sets)
			if err != nil || got.BitLength != 3 || !bytes.Equal(got.Bytes, tc.want) {
				t.Fatalf("got %#v, %v", got, err)
			}
			if !bytes.Equal(tc.value.Bytes, before) {
				t.Fatal("changed input")
			}
			got.Bytes[0] ^= 0xff
			if !bytes.Equal(tc.value.Bytes, before) {
				t.Fatal("returned caller storage")
			}
		})
	}
	for _, value := range []runtime.BitString{{BitLength: -1}, {BitLength: 1}, {Bytes: []byte{0}, BitLength: 0}, {Bytes: []byte{0}, BitLength: 9}, {Bytes: []byte{0, 0}, BitLength: 1}} {
		if _, err := NormalizeNamedBitStringForEncoding(value, sets); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("malformed %#v: %v", value, err)
		}
	}
	value := runtime.BitString{Bytes: []byte{0, 0x80}, BitLength: 9}
	if _, err := NormalizeNamedBitStringForEncoding(value, sets); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("excess set bit: %v", err)
	}
}

func TestNewNamedBitStringSourceLength(t *testing.T) {
	sets := []NamedBitSizeSet{{{Min: 3, Max: 3}, {Min: 8, Max: 8}}, {{Min: 5, Max: 9}}}
	for _, set := range [][]int{nil, {0}, {7}, {0, 0, 7}} {
		got, err := NewNamedBitString(sets, set...)
		if err != nil || got.BitLength != 8 || len(got.Bytes) != 1 {
			t.Fatalf("bits %v: %#v, %v", set, got, err)
		}
		for _, bit := range set {
			if !got.Has(bit) {
				t.Fatalf("missing bit %d", bit)
			}
		}
	}
	for _, set := range [][]int{{-1}, {8}, {math.MaxInt}} {
		if _, err := NewNamedBitString(sets, set...); err == nil {
			t.Fatalf("accepted %v", set)
		}
	}
}

func TestNamedBitEncodingToleranceOnlyPermitsSourceSizeFailure(t *testing.T) {
	sets := []NamedBitSizeSet{{{Min: 3, Max: 8}}}
	value := runtime.BitString{Bytes: []byte{0, 0x81}, BitLength: 9}
	var reports ViolationLog
	if _, err := NormalizeNamedBitStringForBEREncoding(value, sets); err == nil {
		t.Fatal("strict normalization accepted significant overflow")
	}
	got, err := NormalizeNamedBitStringForBEREncoding(value, sets, WithTolerance(&reports))
	if err != nil || got.BitLength != 9 || len(got.Bytes) != 2 || got.Bytes[1] != 0x80 || len(reports.Snapshot()) != 0 {
		t.Fatalf("tolerant normalization %+v %v; source checks must publish reports", got, err)
	}
	got.Bytes[1] = 0
	if value.Bytes[1] != 0x81 {
		t.Fatal("tolerant normalization borrowed caller storage")
	}
	for _, invalid := range []struct {
		value runtime.BitString
		sets  []NamedBitSizeSet
	}{
		{runtime.BitString{BitLength: -1}, sets},
		{runtime.BitString{BitLength: 9}, sets},
		{value, []NamedBitSizeSet{{{Min: -1, Max: 8}}}},
		{value, []NamedBitSizeSet{{{Min: 9, Max: 8}}}},
	} {
		if _, err := NormalizeNamedBitStringForBEREncoding(invalid.value, invalid.sets, WithTolerance(&reports)); err == nil {
			t.Fatal("tolerance accepted malformed storage or source intervals")
		}
	}
	if _, err := NormalizeNamedBitStringForBEREncoding(value, sets, nil); err == nil {
		t.Fatal("ignored invalid encode option")
	}
}

func TestNamedBitSizeValidationError(t *testing.T) {
	sets := []NamedBitSizeSet{{{Min: 2, Max: 8}}}
	value := runtime.BitString{Bytes: []byte{0, 0x80}, BitLength: 9}
	for _, f := range []func() (runtime.BitString, error){
		func() (runtime.BitString, error) { return NewNamedBitString(sets, 8) },
		func() (runtime.BitString, error) { return NormalizeNamedBitStringForEncoding(value, sets) },
		func() (runtime.BitString, error) { return NormalizeNamedBitStringForBEREncoding(value, sets) },
	} {
		_, err := f()
		ve, ok := err.(*ValidationError)
		if !ok || !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("error: %T %v", err, err)
		}
		if ve.Constraint != "SIZE (2..8)" || ve.Rule.Clause != "51.5" || ve.ObservedLength == nil || *ve.ObservedLength != 9 || ve.Path != "" {
			t.Fatalf("violation: %+v", ve)
		}
	}
}
