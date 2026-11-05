// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/string_contents_layout_test.go; SHA-256 022e3f782802f3949dd7dca82369c3198140e53b93f4c8c27cccec26ca55e553.
package ber

import (
	"errors"
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
		{"profile state", unsafe.Sizeof(mapProfileState{}), 96},
		{"profile element", unsafe.Sizeof(mapProfileElement{}), 48},
		{"decode configuration", unsafe.Sizeof(decodeConfig{}), 216},
		{"form state", unsafe.Sizeof(berFormState{}), 120},
		{"scan frame", unsafe.Sizeof(berScanFrame{}), 80},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, published layout %d", c.name, c.got, c.want)
		}
	}
}

// Generated preflight still checks the complete structure, but leaves the
// repertoire/FROM intersection to its typed decoder (X.680 (02/2021) §51.7).
// Before that walk, even a bad alphabet must allocate no deferred contents.
func TestGeneratedPreflightLeavesTypedContents(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		for _, wire := range [][]byte{{18, 4, '1', '2', '3', '4'}, {18, 4, 'A', 'A', 'A', 'A'}, {22, 2, 255, 255}, {30, 1, 0}} {
			options := TrackMAPForm([]DecodeOption{mode})
			data, err := OwnGeneratedBERInput(wire, options)
			if err != nil {
				t.Fatal(err)
			}
			_, options, err = PrepareGeneratedBERInput(data, options)
			if err != nil {
				t.Fatal(err)
			}
			config, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			if config.form.mapPending != nil {
				t.Fatal("typed contents inspected before the semantic walk")
			}
		}
	}
}

func TestGeneratedPreflightKeepsStructure(t *testing.T) {
	options := TrackMAPForm(nil)
	wire := []byte{48, 7, 18, 1, 'A', 4, 3, 0, 0}
	data, err := OwnGeneratedBERInput(wire, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = PrepareGeneratedBERInput(data, options); err == nil {
		t.Fatal("accepted truncated later sibling")
	}
}

func TestGeneratedRejectedRestrictedContents(t *testing.T) {
	for _, wire := range [][]byte{{23, 0}, {24, 0}, {55, 0}, {56, 0}, {18, 1, 'A'}, {22, 1, 255}} {
		options := TrackMAPForm(nil)
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(data, "MAP-Test.Root", options)
		if err := LocateDecodeError(ErrUnexpectedElement, options); !errors.Is(err, ErrInvalidValue) || errors.Is(err, ErrUnexpectedElement) {
			t.Fatalf("rejected restricted value: %v", err)
		}
	}
}

func TestGeneratedRejectionScansOnce(t *testing.T) {
	measure := func(depth uint32) float64 {
		return testing.AllocsPerRun(20, func() {
			var log ViolationLog
			options, _ := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
			options = TrackMAPForm(options)
			data, err := OwnGeneratedBERInput([]byte{18, 1, 'A'}, options)
			if err != nil {
				t.Fatal(err)
			}
			data, options, err = PrepareGeneratedBERInput(data, options)
			if err != nil {
				t.Fatal(err)
			}
			options = LocateDecodedElement(data, "MAP-Test.Root", options)
			config, err := decodeOptions(options)
			if err != nil {
				t.Fatal(err)
			}
			config.form.mapDepth = depth
			for range depth {
				if err := finishMAPDecode(ErrUnexpectedElement, config); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	shallow, deep := measure(1), measure(64)
	if deep > shallow {
		t.Fatalf("repeated rejection checks allocate per entry: shallow=%.0f deep=%.0f", shallow, deep)
	}
}
