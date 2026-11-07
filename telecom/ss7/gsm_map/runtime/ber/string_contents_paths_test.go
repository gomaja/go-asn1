// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/string_contents_paths_test.go; SHA-256 980fedca18fd4497470d01882f933a5b954e60a926dc980678a45f512030aab0.
package ber

import (
	"errors"
	"testing"
)

func TestGeneratedContentsFailureWaitsForRoot(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		root := []byte{48, 5, 48, 3, 18, 1, 'A'}
		options := TrackMAPForm([]DecodeOption{mode})
		data, err := OwnGeneratedBERInput(root, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		options = LocateDecodedElement(data, "Synthetic.Root", options)
		MarkPreflightTarget(options, "same", data[2:])
		childOptions := []DecodeOption{ChildDecodeContext(options, "same")}
		child, childOptions, err := PrepareGeneratedBERInput(data[2:], childOptions)
		if err != nil {
			t.Fatal(err)
		}
		childOptions = LocateDecodedElement(child, "Synthetic.Child", childOptions)
		// The rejected child's local component has the same name as its parent.
		MarkPreflightTarget(childOptions, "same", child[2:])
		leafOptions := []DecodeOption{ChildDecodeContext(childOptions, "same")}
		leaf, leafOptions, err := PrepareGeneratedBERInput(child[2:], leafOptions)
		if err != nil {
			t.Fatal(err)
		}
		leafOptions = LocateDecodedElement(leaf, "Synthetic.Leaf", leafOptions)
		err = LocateDecodeError(ErrUnexpectedElement, leafOptions)
		if !errors.Is(err, ErrUnexpectedElement) {
			t.Fatalf("inner entry replaced its local error: %v", err)
		}
		var path interface{ ASN1BERPath() string }
		if errors.As(err, &path) {
			t.Fatalf("inner entry exposed root contents path %q", path.ASN1BERPath())
		}
		err = LocateDecodeError(err, childOptions)
		if !errors.Is(err, ErrUnexpectedElement) {
			t.Fatalf("middle entry replaced its local error: %v", err)
		}
		err = LocateDecodeError(err, options)
		var located *ElementError
		if !errors.Is(err, ErrInvalidValue) || errors.Is(err, ErrUnexpectedElement) || !errors.As(err, &located) || located.Offset() != 4 {
			t.Fatalf("lost contents error: %v", err)
		}
		if !errors.As(err, &path) || path.ASN1BERPath() != "same.same" {
			t.Fatalf("root contents path: %v", err)
		}
	}
}
