// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/misplaced_component_test.go; SHA-256 3e8e11b0af43c4da58155d6d8c1e26a44324edcb3f8969f88a8186ed930b74bb.
package ber

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Q.773 (06/1997) §4.1.1 governs TCAP fields; X.690 (02/2021)
// §8.15 assigns the complete open value to the TC-user's syntax.
func TestMisplacedComponentOpenValues(t *testing.T) {
	type message struct {
		name, root string
		identifier byte
		ids        []byte
	}
	messages := []message{
		{"begin", "Begin", 0x62, []byte{0x48, 1, 1}},
		{"end", "End", 0x64, []byte{0x49, 1, 1}},
		{"continue", "Continue", 0x65, []byte{0x48, 1, 1, 0x49, 1, 2}},
		{"unidirectional", "Unidirectional", 0x61, nil},
		{"abort", "Abort", 0x67, []byte{0x49, 1, 1}},
	}
	values := []string{"048103616263", "24050403616263", "3006048103616263"}
	for _, m := range messages {
		prefixes := map[string][]byte{
			"in-place":                 m.ids,
			"extra-element":            append(append([]byte{}, m.ids...), 5, 0),
			"wrong-transaction-id":     {0x4a, 1, 0},
			"missing-transaction-id":   nil,
			"duplicate-portion":        append(append([]byte{}, m.ids...), 0x6c, 0),
			"after-reordered-dialogue": append(append([]byte{}, m.ids...), 0x6c, 0, 0x6b, 7, 0x28, 5, 6, 1, 0x2a, 0x81, 0),
		}
		if m.name == "continue" {
			prefixes["missing-dtid"] = []byte{0x48, 1, 1}
		}
		for position, prefix := range prefixes {
			for _, identifier := range []byte{0xa1, 0xa2, 0xa7, 0xa3} {
				for valueIndex, encoded := range values {
					value, err := hex.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					fields := []byte{2, 1, 0, 2, 1, 0}
					if identifier == 0xa2 || identifier == 0xa7 {
						fields = append([]byte{2, 1, 0}, associatedCardinalityTLV(0x30, append([]byte{2, 1, 0}, value...), false)...)
					} else {
						fields = append(fields, value...)
					}
					portion := associatedCardinalityTLV(0x6c, associatedCardinalityTLV(identifier, fields, false), false)
					for _, root := range []string{"TCMessage", m.root} {
						outer := m.identifier
						if root != "TCMessage" {
							outer = 0x30
						}
						wire := associatedCardinalityTLV(outer, append(append([]byte{}, prefix...), portion...), false)
						t.Run(fmt.Sprintf("%s/%s/component-%x/value-%d/root-%s", m.name, position, identifier, valueIndex, root), func(t *testing.T) {
							checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, root)...), nil)
							var log ViolationLog
							checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, root)...), nil)
							if len(log.Snapshot()) != 0 {
								t.Fatalf("TC-user value acquired profile reports: %+v", log.Snapshot())
							}
						})
					}
				}
			}
		}
	}
}

func TestMisplacedComponentRetainsOwnedFields(t *testing.T) {
	// The Invoke opcode remains TCAP-owned after the portion is misplaced.
	wire, err := hex.DecodeString("621548010105006c0ea10c020100028101000403616263")
	if err != nil {
		t.Fatal(err)
	}
	checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), ErrInvalidValue)
	// The foreign value still has to satisfy X.690 §8.3.1's INTEGER contents rule.
	wire, err = hex.DecodeString("621148010105006c0aa1080201000201000200")
	if err != nil {
		t.Fatal(err)
	}
	checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), ErrInvalidValue)
}

func TestMisplacedLinkedInvokeOpenValues(t *testing.T) {
	for _, linked := range []string{"", "800100", "8100"} {
		link, err := hex.DecodeString(linked)
		if err != nil {
			t.Fatal(err)
		}
		for _, valueHex := range []string{"048103616263", "24050403616263"} {
			value, err := hex.DecodeString(valueHex)
			if err != nil {
				t.Fatal(err)
			}
			fields := append([]byte{2, 1, 0}, link...)
			fields = append(fields, 2, 1, 0)
			fields = append(fields, value...)
			portion := associatedCardinalityTLV(0x6c, associatedCardinalityTLV(0xa1, fields, false), false)
			for _, message := range []struct {
				identifier byte
				root       string
				prefix     []byte
			}{
				{0x62, "Begin", []byte{0x48, 1, 1, 5, 0}},
				{0x64, "End", []byte{0x49, 1, 1, 5, 0}},
				{0x65, "Continue", []byte{0x48, 1, 1}},
				{0x61, "Unidirectional", []byte{5, 0}},
				{0x67, "Abort", []byte{0x49, 1, 1}},
			} {
				for _, root := range []string{"TCMessage", message.root} {
					identifier := message.identifier
					if root != "TCMessage" {
						identifier = 0x30
					}
					wire := associatedCardinalityTLV(identifier, append(append([]byte{}, message.prefix...), portion...), false)
					t.Run(fmt.Sprintf("%s/linked-%s/value-%s", root, linked, valueHex), func(t *testing.T) {
						checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, root)...), nil)
					})
				}
			}
		}
	}
}

func TestMisplacedPortionDoesNotInferUnadmittedForms(t *testing.T) {
	// These tags are outside the transaction grammar. Retaining the TC-user
	// boundary must not assign an IMPLICIT base type to an unadmitted field.
	for _, encoded := range []string{
		"620948010105006c028100",
		"620b48010105006c04a1028000",
		"620948010105006c028700",
	} {
		wire, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), nil)
	}
}

// Q.773 (06/1997) §4.1.1 has no fields below an unadmitted message
// alternative. X.690 (02/2021) §8.15 retains the TC-user's encoding.
func TestUnknownMessageHasNoOwnedFields(t *testing.T) {
	for _, valueHex := range []string{"048103616263", "24050403616263", "3006048103616263"} {
		value, err := hex.DecodeString(valueHex)
		if err != nil {
			t.Fatal(err)
		}
		for _, component := range []byte{0xa1, 0xa2, 0xa7, 0xa3} {
			fields := append([]byte{2, 1, 0, 2, 1, 0}, value...)
			if component == 0xa2 || component == 0xa7 {
				fields = append([]byte{2, 1, 0}, associatedCardinalityTLV(0x30, append([]byte{2, 1, 0}, value...), false)...)
			}
			portion := associatedCardinalityTLV(0x6c, associatedCardinalityTLV(component, fields, false), false)
			for _, outer := range []byte{0x60, 0x63, 0x66, 0x68} {
				wire := associatedCardinalityTLV(outer, append([]byte{0x48, 1, 1}, portion...), false)
				for _, root := range []string{"", "TCMessage"} {
					checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, root)...), nil)
					var log ViolationLog
					checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, root)...), nil)
					if len(log.Snapshot()) != 0 {
						t.Fatalf("unknown message %x acquired profile reports: %+v", wire, log.Snapshot())
					}
				}
			}
		}
	}
	// Even fields resembling component opcode and transaction ID headers have
	// no TCAP ownership below an unadmitted outer alternative.
	for _, encoded := range []string{"63134801016c0ea10c020100028101000403616263", "630448810101"} {
		wire, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), nil)
	}
}
