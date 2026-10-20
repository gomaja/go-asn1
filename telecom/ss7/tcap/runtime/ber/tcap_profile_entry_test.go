// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_profile_entry_test.go; SHA-256 2b0bb8488951ed64b8921166f2aba63fae13060df5756a2e9dd5ffe29838c188.
package ber

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

// Q.773 (06/1997) Annex A, §§3.2, 4.1.1 and X.690 (02/2021) §8.15:
// a whole-message scan owns the dialogue syntax but not component open types.
func TestTCAPProfileDefaultEntry(t *testing.T) {
	for _, tc := range []struct {
		name, wire, rule string
		offset           int
		indexes          []int
	}{
		{name: "invoke argument", wire: "62104801016c0ba1090201010201016b8100"},
		{name: "result value", wire: "64184904000000016c10a20e0201013009020102308103040100"},
		{name: "error parameter", wire: "64164904000000016c0ea30c020101020105308103040100"},
		{name: "dialogue APDU", wire: "67174901026b122810060700118605010101a0052303800100", rule: "primitive-bit-string", offset: 20, indexes: []int{1, 0, 1, 0}},
		{name: "constructed OTID", wire: "6206680404020102", rule: "primitive-octet-string", offset: 2, indexes: []int{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range [][]string{nil, {""}, {"", "TCAPMessages"}, {"TCMessage"}, {"TCMessage", "TCAPMessages", "TCMessage"}} {
				err = ValidateBERElement(data, TrackTCAPForm(nil, source...)...)
				if tc.rule == "" {
					if err != nil {
						t.Fatalf("source=%q: %v", source, err)
					}
					continue
				}
				var failure *ValidationError
				var located *ElementError
				if !errors.As(err, &failure) || failure.Constraint != "Q.773 §4.1.1: "+tc.rule || !errors.As(err, &located) || located.Offset() != tc.offset || !slices.Equal(located.ChildIndexes(), tc.indexes) {
					t.Fatalf("source=%q: wrong rule/location: %v, %+v", source, err, located)
				}
			}
		})
	}
}

func TestTCAPProfileDefaultPreservesActiveSubtree(t *testing.T) {
	data, err := hex.DecodeString("a1090201010201016b8100")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [][]string{nil, {""}} {
		opts := TrackTCAPForm(nil, "Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke")
		opts = TrackTCAPForm(opts, source...)
		if err := ValidateBERElement(data, opts...); err != nil {
			t.Fatal("reapplying profile changed subtree ownership", err)
		}
	}
}
