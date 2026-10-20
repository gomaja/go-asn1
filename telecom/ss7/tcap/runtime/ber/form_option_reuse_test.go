// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/form_option_reuse_test.go; SHA-256 b0d386610961f2eff42bdedbcde7551195e77ac4338685e723f230d2d3a001b3.
package ber

import (
	"reflect"
	"testing"
)

func TestTCAPFormCallerStateIsNotDecodeState(t *testing.T) {
	options := TrackTCAPForm(nil)
	form, ok := options[len(options)-1].(berFormOption)
	if !ok || form.state == nil {
		t.Fatal("missing form option")
	}
	wire := []byte{0x62, 0x80, 0x48, 0x01, 0x01, 0x00, 0x00}
	for range 2 {
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*form.state, berFormState{}) {
			t.Fatalf("standalone scan mutated caller form state: %+v", form.state)
		}
	}
	root := TrackTCAPForm(options)
	rootForm, ok := root[len(root)-1].(berFormOption)
	if !ok || rootForm.state == form.state {
		t.Fatal("generated root inherited caller form state")
	}
	owned, err := OwnGeneratedBERInput(wire, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareGeneratedBERInput(owned, root); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*form.state, berFormState{}) {
		t.Fatalf("generated root mutated caller form state: %+v", form.state)
	}
}

func TestTCAPFormClonesEveryCallerMarker(t *testing.T) {
	first := TrackTCAPForm(nil)
	second := TrackTCAPForm(nil)
	original := append(first[:len(first):len(first)], second[len(second)-1])
	root := TrackTCAPForm(original)
	for _, index := range []int{len(first) - 1, len(root) - 1} {
		old := original[index].(berFormOption).state
		fresh := root[index].(berFormOption).state
		if old == fresh {
			t.Fatalf("form marker %d still shares caller state", index)
		}
	}
	wire := []byte{0x62, 0x03, 0x48, 0x01, 0x01}
	owned, err := OwnGeneratedBERInput(wire, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareGeneratedBERInput(owned, root); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{len(first) - 1, len(root) - 1} {
		if state := original[index].(berFormOption).state; !reflect.DeepEqual(*state, berFormState{}) {
			t.Fatalf("caller form marker %d was modified: %+v", index, state)
		}
	}
}
