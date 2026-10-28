package tcap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// These synthetic malformed values pin diagnostics; they introduce no wire rules.
func TestDecodeErrorTextNamesPathOnce(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{"620648027f016c", "decoding TCMessage: ber: unexpected end of data"},
		{"620648027f010500", "decoding begin: ber: decode Begin at offset 4: ber: unexpected or missing element"},
		{"650648027f010500", "decoding continue: ber: unexpected or missing element: expected tag [APPLICATION 9] for dtid, got [UNIVERSAL 5 PRIMITIVE]"},
		{"620b48027f016c05a10302010a", "decoding begin.components.element[0].basicROS.invoke: ber: unexpected or missing element: missing required field opcode"},
		{"620548027f0105", "decoding child[1]: ber: unexpected end of data"},
		{"620548027f0100", "decoding child[1]: ber: unexpected end of data"},
		{"62020500", "decoding begin: ber: unexpected or missing element: expected tag [APPLICATION 8] for otid, got [UNIVERSAL 5 PRIMITIVE]"},
		{"6200", "decoding begin: ber: unexpected or missing element: missing required field otid"},
		{"620848027f0105006c00", "decoding begin: ber: decode Begin at offset 4: ber: unexpected or missing element"},
		{"620448807f01", "decoding begin.otid: ber: invalid length encoding: indefinite length used with primitive tag [APPLICATION 8 PRIMITIVE]"},
		{"620748050102030405", "decoding begin.otid: begin.otid length 5 violates SIZE (1..4)"},
		{"620448027f0100", "decoding TCMessage: ber: trailing data after value"},
		{"628048027f01", "decoding TCMessage: ber: unexpected end of data"},
		{"628048027f010000", ""},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, options := range [][]ber.DecodeOption{nil, {ber.ForceGeneratedBERLightForTesting()}, {ber.ForceGeneratedBERProofForTesting()}, {ber.WithoutReplayCapture()}} {
				var value TCMessage
				failure := value.UnmarshalBER(data, options...)
				if failure == nil {
					if tc.want != "" {
						t.Fatalf("decode succeeded, want %q", tc.want)
					}
					continue
				}
				var chain []error
				for current := failure; current != nil; current = errors.Unwrap(current) {
					chain = append(chain, current)
				}
				got := failure.Error()
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				for current, index := failure, 0; current != nil; current, index = errors.Unwrap(current), index+1 {
					if current != chain[index] {
						t.Fatal("formatting changed error chain")
					}
				}
			}
		})
	}
}

func TestDecodeErrorFormattingRetainsCause(t *testing.T) {
	sentinel := errors.New("failure")
	for _, cause := range []error{sentinel, fmt.Errorf("context: %w", sentinel), nil} {
		failure := &DecodeError{Path: "begin", Cause: cause}
		if got, want := failure.Error(), fmt.Sprintf("decoding begin: %v", cause); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
		if errors.Unwrap(failure) != cause || errors.Is(failure, sentinel) != errors.Is(cause, sentinel) {
			t.Fatal("cause matching changed")
		}
	}
	inner := &berPathError{segment: "inside", phase: "decoding", cause: sentinel}
	options := ber.LocateDecodedElement([]byte{5, 0}, "Root", nil)
	located := ber.LocateDecodeError(inner, options)
	var element *ber.ElementError
	if !errors.As(located, &element) {
		t.Fatal("fixture has no transparent element location")
	}
	outer := &berPathError{segment: "outside", phase: "decoding", cause: located}
	failure := &DecodeError{Path: outer.ASN1BERPath(), Cause: outer}
	if got, want := failure.Error(), "decoding outside.inside: failure"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got, want := outer.Error(), "decoding outside.inside: failure"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	var retained *ber.ElementError
	if !errors.As(failure, &retained) || retained != element || !errors.Is(failure, sentinel) || !reflect.DeepEqual(element.ChildIndexes(), retained.ChildIndexes()) {
		t.Fatal("location or cause changed")
	}
}

func TestDecodeErrorFormattingAllocationCounts(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts vary under the race detector, whose sync.Pool drops values at random")
	}
	for _, wire := range []string{"620648027f016c", "620648027f010500", "650648027f010500", "620b48027f016c05a10302010a", "628048027f010000"} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		var text string
		// Compare the two formatters around the same decoder and runtime. Direct
		// emission and the pruned publication can have different escape costs.
		measure := func(original bool) float64 {
			return testing.AllocsPerRun(20, func() {
				var value TCMessage
				if err := value.UnmarshalBER(data); err != nil {
					if original {
						failure, ok := err.(*DecodeError)
						if !ok {
							panic("missing DecodeError")
						}
						text = fmt.Sprintf("decoding %s: %v", failure.Path, failure.Cause)
					} else {
						text = err.Error()
					}
				}
			})
		}
		before, after := measure(true), measure(false)
		if after > before {
			t.Fatalf("%s: formatting allocations grew from %g to %g", wire, before, after)
		}
		if wire != "628048027f010000" && text == "" {
			t.Fatal("missing formatted error")
		}
	}
}

type terminalBERPathError struct{}

func (terminalBERPathError) Error() string       { return "terminal failure" }
func (terminalBERPathError) ASN1BERPath() string { return "inside" }
func TestDecodeErrorTerminalPathCause(t *testing.T) {
	cause := terminalBERPathError{}
	failure := &DecodeError{Path: "inside", Cause: cause}
	if got, want := failure.Error(), "decoding inside: terminal failure"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDecodeErrorFormattingGrowth(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts vary under the race detector, whose sync.Pool drops values at random")
	}
	var baseline float64
	for _, depth := range []int{256, 1024, 4096} {
		leaf := errors.New("failure")
		cause := leaf
		for range depth {
			cause = &berPathError{segment: "part", phase: "decoding", cause: cause}
		}
		path := cause.(interface{ ASN1BERPath() string }).ASN1BERPath()
		failure := &DecodeError{Path: path, Cause: cause}
		want := "decoding " + strings.TrimSuffix(strings.Repeat("part.", depth), ".") + ": failure"
		if got := failure.Error(); got != want {
			t.Fatalf("depth %d: diagnostic differs", depth)
		}
		var text string
		got := testing.AllocsPerRun(20, func() { text = failure.Error() })
		if baseline == 0 {
			baseline = got
		}
		if limit := baseline * float64(depth) / 256; got > limit {
			t.Fatalf("depth %d: %g formatting allocations exceed linear bound %g", depth, got, limit)
		}
		if len(text) != len(want) {
			t.Fatal("formatting changed length")
		}
	}
}
