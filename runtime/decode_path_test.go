package runtime

import (
	"errors"
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
