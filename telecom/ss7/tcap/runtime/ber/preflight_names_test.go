// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/preflight_names_test.go; SHA-256 81b88ab64e0bbbc37690fa3493e283eebaa96b2975cb4a4ea590622bfc1eeebc.
package ber

import (
	"errors"
	"strings"
	"testing"
)

// Q.773 (06/1997) §§3.2.1, 4.1.1 and X.690 (02/2021) §8.18:
// an ordinary BER failure keeps names down to the untyped open value.
func TestTCAPPreflightContentsNames(t *testing.T) {

	// Build the envelopes from their contents so the synthetic lengths stay exact.
	wrap := func(identifier byte, contents []byte) []byte {
		return append(append([]byte{identifier}, EncodeLength(len(contents))...), contents...)
	}
	foreign := wrap(0x28, append([]byte{6, 2, 0x2a, 3}, wrap(0xa0, []byte{0x0c, 2, 0xc0, 0x80})...))
	apdu := wrap(0x60, append([]byte{0xa1, 9, 6, 7, 4, 0, 0, 1, 0, 19, 2}, wrap(0xbe, foreign)...))
	ext := wrap(0x28, append([]byte{6, 7, 0, 17, 134, 5, 1, 1, 1}, wrap(0xa0, apdu)...))
	wire := wrap(0x62, append([]byte{0x48, 1, 1}, wrap(0x6b, ext)...))
	options := TrackTCAPForm(nil, "TCMessage", "TCAPMessages", "TCMessage")
	cause := ValidateBERElement(wire, options...)
	var original *ElementError
	if !errors.As(cause, &original) || !errors.Is(cause, ErrInvalidValue) {
		t.Fatalf("cause: %v", cause)
	}
	err := DiagnosePreflight(cause, wire, options, "child", func([]DecodeOption) error { return nil })
	want := "begin.dialoguePortion.encoding.single-ASN1-type.dialogueRequest.user-information.element[0].encoding.single-ASN1-type"
	if !strings.HasPrefix(err.Error(), "decoding "+want+": ") {
		t.Fatalf("path: %v", err)
	}
	var retained *ElementError
	if !errors.As(err, &retained) || retained != original || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("changed cause: %v", err)
	}
}

func FuzzTCAPDiagnosticNames(f *testing.F) {
	for _, seed := range [][]byte{{0x62, 3, 0x48, 1, 1}, {0x64, 3, 0x80, 1, 0}, {0xb0, 2, 5, 0}, {0xb3, 2, 5, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		for _, root := range []string{"TCMessage", "Begin", "ABRTApdu", "DialoguePortion", "Bind", "Unbind"} {
			options := TrackTCAPForm([]DecodeOption{WithDecodeLimits(DecodeLimits{MaxDepth: 16, MaxElements: 1024, MaxWork: 65536})}, root, "Synthetic-Names", root)
			cause := ValidateBERElement(data, options...)
			err := DiagnosePreflight(cause, data, options, "child", func([]DecodeOption) error { return nil })
			if (err == nil) != (cause == nil) {
				t.Fatalf("changed verdict: %v -> %v", cause, err)
			}
			for _, sentinel := range []error{ErrInvalidValue, ErrInvalidTag, ErrInvalidLength, ErrTruncated, ErrUnexpectedElement, ErrIndefiniteLength, ErrExtraData, ErrUnsupported, ErrResourceLimit} {
				if errors.Is(cause, sentinel) != errors.Is(err, sentinel) {
					t.Fatalf("changed sentinel: %v -> %v", cause, err)
				}
			}
			var before, after *ElementError
			if errors.As(cause, &before) != errors.As(err, &after) || before != after {
				t.Fatalf("changed location cause: %v -> %v", cause, err)
			}
		}
	})
}

// X.880 (07/1994) Annex A names these explicitly tagged open alternatives.
func TestTCAPPreflightOpenAlternatives(t *testing.T) {
	for _, row := range []struct {
		root, path string
		identifier byte
	}{
		{"Bind", "bind-invoke", 0xb0}, {"Bind", "bind-result", 0xb1}, {"Bind", "bind-error", 0xb2},
		{"Unbind", "unbind-invoke", 0xb3}, {"Unbind", "unbind-result", 0xb4}, {"Unbind", "unbind-error", 0xb5},
	} {
		wire := []byte{row.identifier, 3, 5, 1, 0}
		opts := TrackTCAPForm(nil, row.root, "Remote-Operations-Generic-ROS-PDUs", row.root)
		cause := ValidateBERElement(wire, opts...)
		err := DiagnosePreflight(cause, wire, opts, "child", func([]DecodeOption) error { return nil })
		if err == nil || !strings.HasPrefix(err.Error(), "decoding "+row.path+": ") || !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("%s: %v", row.path, err)
		}
	}
}

// X.880 (07/1994) Annex A: after opcode, ANY is the argument even when
// its tag is also used by opcode or linkedId. Its nested contents stay open.
func TestTCAPArgumentNamesUsePosition(t *testing.T) {
	for _, row := range []struct {
		wire []byte
		path string
	}{
		{[]byte{0x30, 8, 2, 1, 1, 2, 1, 1, 2, 0}, "argument"},
		{[]byte{0x30, 10, 2, 1, 1, 2, 1, 1, 0xa0, 2, 2, 0}, "argument.child[0]"},
	} {
		opts := TrackTCAPForm(nil, "Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke")
		cause := ValidateBERElement(row.wire, opts...)
		err := DiagnosePreflight(cause, row.wire, opts, "child", func([]DecodeOption) error { return nil })
		if err == nil || !strings.HasPrefix(err.Error(), "decoding "+row.path+": ") || !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("%s: %v", row.path, err)
		}
	}
}
