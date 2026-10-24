// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/decode_path_test.go; SHA-256 6367b7b2e1ff41ee932e632833fb375f3b815f864b9913e6f9fbd53395cdac34.
package runtime

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestWrapDecodePathBuildsCanonicalNestedPath(t *testing.T) {
	cause := errors.New("malformed value")
	err := WrapDecodePath(cause, "ExtensionValue")
	err = WrapDecodePath(err, "IEExtensions[0]")
	err = WrapDecodePath(err, "Message")

	if got, want := err.Error(), "decoding Message.IEExtensions[0].ExtensionValue: malformed value"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped decode path does not preserve its cause")
	}
}

func TestWrapDecodePathHandlesIndexAndNil(t *testing.T) {
	cause := errors.New("malformed value")
	indexed := WrapDecodePath(cause, "Items[2]")
	err := WrapDecodePath(indexed, "Items")
	if got, want := err.Error(), "decoding Items[2]: malformed value"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if WrapDecodePath(nil, "Message") != nil {
		t.Fatal("wrapping nil returned a non-nil error")
	}
}

func TestWrapDecodePathPreservesRepeatedNamedSegments(t *testing.T) {
	cause := errors.New("malformed value")
	err := WrapDecodePath(cause, "GNBID")
	err = WrapDecodePath(err, "GNBID")
	err = WrapDecodePath(err, "GlobalGNBID")

	if got, want := err.Error(), "decoding GlobalGNBID.GNBID.GNBID: malformed value"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

type pathAwareError struct{ path string }

func (e pathAwareError) Error() string                    { return e.path }
func (e pathAwareError) WithDecodePath(path string) error { return pathAwareError{path: path} }

func TestWrapDecodePathUpdatesOwnedLocation(t *testing.T) {
	original := pathAwareError{}
	err := WrapDecodePath(WrapDecodePath(original, "IEs[2]"), "Message")
	var located pathAwareError
	if !errors.As(err, &located) || located.path != "Message.IEs[2]" {
		t.Fatalf("owned location was not qualified: %v", err)
	}
	if original.path != "" {
		t.Fatal("ancestor changed original error")
	}
}

func TestWrapDecodePathKeepsIntermediateErrorContext(t *testing.T) {
	original := pathAwareError{}
	err := WrapDecodePath(fmt.Errorf("known IE body: %w", original), "Message.IEs[2]")
	var located pathAwareError
	if !errors.As(err, &located) || located.path != "Message.IEs[2]" || !strings.Contains(err.Error(), "known IE body:") || !errors.Is(err, original) {
		t.Fatalf("lost error context: %v, %+v", err, located)
	}
}
