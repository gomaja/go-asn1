// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/choice_observation_test.go; SHA-256 d5aa1c5a42a153843073926d86094b2efad480c06acb836ec60b72868ed4e7eb.
package aper

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestChoiceExtensionObservationPath(t *testing.T) {
	for _, mode := range []struct {
		name    string
		options []DecodeOption
	}{
		{"strict", nil}, {"receiver", []DecodeOption{WithReceiverMode()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			wire := []byte{1, 0xa5}
			bb := NewBitBufferFromBytes(wire)
			state := ApplyDecodeOptions(mode.options...)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			extension, err := DecodeChoiceExtensionAligned(bb, 7, 0)
			report, err := FinishDecode(state, err)
			if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			observation := report.Observations[0]
			origin := extension.Origin()
			if observation.Location.Path != "UnknownExtension" {
				t.Errorf("observation path=%q, want UnknownExtension", observation.Location.Path)
			}
			if origin.Location.Path != "UnknownExtension" || !reflect.DeepEqual(observation.Location, origin.Location) {
				t.Errorf("observation location=%+v, retained=%+v", observation.Location, origin.Location)
			}
			if observation.Kind != UnknownExtension || observation.Rule != (SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§23.8"}) || !observation.Location.HasWireLocation || !reflect.DeepEqual(observation.Location.Spans, []BitSpan{{Start: 0, End: 16}}) {
				t.Errorf("observation=%+v", observation)
			}
			if extension.Index() != 7 || !bytes.Equal(extension.Contents(), []byte{0xa5}) {
				t.Errorf("extension=%+v", extension)
			}
			encoded := NewBitBuffer()
			if err := extension.EncodeTo(encoded); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), wire) {
				t.Errorf("replay=%x want=%x", encoded.Bytes(), wire)
			}
		})
	}
}

// X.691 (02/2021) §23.8 uses the same framing for every extension arm;
// the schema, not the extension bit alone, determines whether it is unknown.
func TestChoiceExtensionKnownAlternativeHasNoObservation(t *testing.T) {
	for _, options := range [][]DecodeOption{nil, {WithReceiverMode()}} {
		bb := NewBitBufferFromBytes([]byte{1, 0xa5})
		state := ApplyDecodeOptions(options...)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		value, err := DecodeChoiceExtensionAligned(bb, 1, 2)
		report, err := FinishDecode(state, err)
		if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || state.Usage().Reports != 0 {
			t.Errorf("known alternative report=%+v err=%v", report, err)
		}
		if value.Index() != 1 || !bytes.Equal(value.Contents(), []byte{0xa5}) || bb.BitPos() != 16 {
			t.Errorf("known alternative=%+v position=%d", value, bb.BitPos())
		}
	}
}

func TestChoiceExtensionSchemaAndOpenTypeLimits(t *testing.T) {
	for _, test := range []struct {
		name         string
		index, known int64
	}{
		{"negative index", -1, 2}, {"negative schema count", 0, -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{1, 0xa5})
			if _, err := DecodeChoiceExtensionAligned(bb, test.index, test.known); !errors.Is(err, ErrInvalidValue) || bb.BitPos() != 0 {
				t.Fatalf("invalid schema err=%v position=%d", err, bb.BitPos())
			}
		})
	}
	for _, index := range []int64{0, 2} {
		bb := NewBitBufferFromBytes([]byte{2, 0xa5, 0x5a})
		state := ApplyDecodeOptions(WithLimits(Limits{MaxOpenTypeBytes: 1}))
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		_, err := DecodeChoiceExtensionAligned(bb, index, 2)
		report, err := FinishDecode(state, err)
		if !errors.Is(err, ErrLimit) || len(report.Observations) != 0 {
			t.Errorf("index=%d report=%+v err=%v", index, report, err)
		}
	}
}
