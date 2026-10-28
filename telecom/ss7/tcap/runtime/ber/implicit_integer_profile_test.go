// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/implicit_integer_profile_test.go; SHA-256 2d84f89f90e84b0a5e75b815fc8acb5d31f96b6e68931d7b3f74d3bbf091cdab.
package ber

import (
	"encoding/hex"
	"errors"
	"testing"
)

// X.690 (02/2021) §§8.3.1–8.3.2 apply after IMPLICIT tagging.
// The root and child assignments come from TCAPMessages, DialoguePDUs and
// Remote-Operations-Generic-ROS-PDUs, all with their source tag modes.
func TestProfileImplicitIntegerContents(t *testing.T) {
	for _, tc := range []struct {
		name, root, wire string
		want             error
	}{
		{"P-Abort cause", "TCMessage", "67054901014a00", ErrInvalidValue},
		{"P-Abort sign octet", "TCMessage", "67074901014a020001", ErrInvalidValue},
		{"Invoke linkedId", "TCMessage", "640f4901016c0aa108020101800002012d", ErrInvalidValue},
		{"Reject problem", "Reject", "a4050201018000", ErrInvalidValue},
		{"ABRT source", "ABRTApdu", "64028000", ErrInvalidValue},
		{"RLRQ reason", "RLRQApdu", "62028000", ErrInvalidValue},
		{"RLRE reason", "RLREApdu", "63028000", ErrInvalidValue},
		{"non-INTEGER primitive", "Begin", "620448000500", nil},
		{"wrong Abort reason root tag", "AbortReason", "4900", nil},
		{"constructed P-Abort empty", "TCMessage", "670449006a00", ErrInvalidTag},
		{"constructed P-Abort value", "TCMessage", "670749006a03020100", ErrInvalidTag},
		{"constructed linkedId", "TCMessage", "62124801016c0da10b020101a00302010002012d", ErrInvalidTag},
		{"constructed Reject problem", "TCMessage", "640f4901016c0aa408020101a003020100", ErrInvalidTag},
		{"Abort reason root", "AbortReason", "4a00", ErrInvalidValue},
		{"Reject problem root", "RejectProblemChoice", "8000", ErrInvalidValue},
		{"constructed Abort reason root", "AbortReason", "6a00", ErrInvalidTag},
		{"constructed Reject problem root", "RejectProblemChoice", "a000", ErrInvalidTag},
		{"valid P-Abort cause", "TCMessage", "67064901014a0101", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			got := ValidateBERElement(data, TrackTCAPForm(nil, tc.root)...)
			assertElementSentinels(t, got, tc.want)
		})
	}
}

func TestProfileImplicitIntegerWorkGrowsWithInput(t *testing.T) {
	baseAllocs := -1.0
	for _, size := range []int{64, 256, 1024, 4096} {
		contents := make([]byte, size)
		for i := range contents {
			contents[i] = 1
		}
		inner := append([]byte{0x80}, EncodeLength(len(contents))...)
		inner = append(inner, contents...)
		wire := append([]byte{0x64}, EncodeLength(len(inner))...)
		wire = append(wire, inner...)
		options := TrackTCAPForm(nil, "ABRTApdu")
		options = append(options, WithDecodeLimits(DecodeLimits{MaxWork: len(wire)}))
		if err := ValidateBERElement(wire, options...); err != nil {
			t.Fatalf("size %d with linear work budget: %v", size, err)
		}
		limited := TrackTCAPForm(nil, "ABRTApdu")
		limited = append(limited, WithDecodeLimits(DecodeLimits{MaxWork: len(wire) - 1}))
		if err := ValidateBERElement(wire, limited...); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("size %d with insufficient work budget: %v", size, err)
		}
		allocs := testing.AllocsPerRun(20, func() {
			if err := ValidateBERElement(wire, options...); err != nil {
				panic(err)
			}
		})
		if baseAllocs < 0 {
			baseAllocs = allocs
		} else if allocs > baseAllocs+1 {
			t.Fatalf("size %d: allocations %.0f exceed small-input %.0f", size, allocs, baseAllocs)
		}
	}
}
