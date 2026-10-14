package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestBERReplayPolicy(t *testing.T) {
	// X.690 (02/2021) §8.1.3.5 Note 2 permits the received long length.
	canonical := []byte{4, 1, 0xaa}
	original := []byte{4, 0x81, 1, 0xaa}
	if got := PreserveEncodedBER(canonical, original, canonical, nil); !bytes.Equal(got, original) {
		t.Fatalf("default replay = %x", got)
	}
	options := []EncodeOption{WithoutBERReplay()}
	if err := ValidateEncodeOptions(options...); err != nil {
		t.Fatal(err)
	}
	if BERReplayEnabled(options) || !BERReplayEnabled(nil) {
		t.Fatal("incorrect explicit/default replay policy")
	}
	if got := PreserveEncodedBER(canonical, original, canonical, options); !bytes.Equal(got, canonical) {
		t.Fatalf("disabled replay = %x", got)
	}
	edited := []byte{4, 1, 0xbb}
	if got := PreserveEncodedBER(edited, original, canonical, nil); !bytes.Equal(got, edited) {
		t.Fatalf("edited value = %x", got)
	}
	if got := PreserveEncodedBER(canonical, nil, canonical, nil); !bytes.Equal(got, canonical) {
		t.Fatalf("fresh value = %x", got)
	}
	replay := PreserveEncodedBER(canonical, original, canonical, nil)
	replay[0] = 0xff
	if original[0] != 4 {
		t.Fatal("replay aliases retained original")
	}
	if BERReplayEnabled([]EncodeOption{nil}) {
		t.Fatal("malformed options permit replay")
	}
}

func TestBERReplayPolicyReachesChildrenAndStages(t *testing.T) {
	// Constructed OCTET STRING and indefinite SEQUENCE: X.690 (02/2021)
	// §§8.7.3.2, 8.9.1, 8.1.3.6. The typed encoder chooses definite forms.
	originalChild := []byte{0x24, 0x80, 4, 1, 0xaa, 0, 0}
	value, n, err := DecodeOctetString(originalChild)
	if err != nil || n != len(originalChild) || !bytes.Equal(value, []byte{0xaa}) {
		t.Fatalf("typed decode %x/%d: %v", value, n, err)
	}
	canonicalChild, err := EncodeOctetString(value)
	if err != nil {
		t.Fatal(err)
	}
	originalParent := append([]byte{0x30, 0x80}, originalChild...)
	originalParent = append(originalParent, 0, 0)
	snapshotParent := policySequence(t, originalChild)
	for _, disabled := range []bool{false, true} {
		var log ViolationLog
		options := []EncodeOption{WithConstraintTolerance(&log)}
		if disabled {
			options = append(options, WithoutBERReplay())
		}
		options, finish := StageEncodeReports(options)
		childOptions := ChildEncodeOptions(options, "items")
		childOptions = ParentCollectionSizeEncodeOptions(childOptions)
		childOptions = ChildEncodeOptions(childOptions, "[0]")
		childOptions, childFinish := StageEncodeReports(childOptions)
		if BERReplayEnabled(childOptions) == disabled {
			t.Fatal("child/staging lost policy")
		}
		child := PreserveEncodedBER(canonicalChild, originalChild, canonicalChild, childOptions)
		parent := PreserveEncodedBER(policySequence(t, child), originalParent, snapshotParent, options)
		want := originalParent
		if disabled {
			want = policySequence(t, canonicalChild)
		}
		if !bytes.Equal(parent, want) {
			t.Fatalf("disabled=%t: nested encoding=%x want=%x", disabled, parent, want)
		}
		// Tolerance still requires explicit reports even when replay is disabled.
		if err := CheckEncodedValue(childOptions, "id", "(0)", "1"); err != nil {
			t.Fatal(err)
		}
		childFinish(true)
		finish(true)
		reports := log.Snapshot()
		if len(reports) != 1 || reports[0].Path != "items.[0].id" {
			t.Fatalf("reports = %+v", reports)
		}
	}
}

func TestBERReplayPolicyRefusesOpaqueValues(t *testing.T) {
	for _, options := range [][]EncodeOption{
		{WithoutBERReplay()},
		ChildEncodeOptions([]EncodeOption{WithoutBERReplay()}, "open"),
		ChildEncodeOptions([]EncodeOption{WithoutBERReplay()}, "extensions"),
	} {
		if err := CheckBEROpaqueReplay(options...); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("opaque replay error=%v", err)
		}
	}
	if err := CheckBEROpaqueReplay(); err != nil {
		t.Fatalf("default opaque replay=%v", err)
	}
	if err := CheckBEROpaqueReplay(nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("malformed option=%v", err)
	}
	var log ViolationLog
	if err := CheckBEROpaqueReplay(WithoutBERReplay(), WithConstraintTolerance(&log)); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("tolerance admitted opaque replay: %v", err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("opaque refusal published subtype reports")
	}
}

func policySequence(t *testing.T, children []byte) []byte {
	t.Helper()
	encoded, err := EncodeSequence(children)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestBERReplayPolicyKeepsStrictConstraintsAndTypedBooleanEdits(t *testing.T) {
	options := []EncodeOption{WithoutBERReplay(), WithoutBERReplay()}
	if err := ValidateEncodeOptions(options...); err != nil {
		t.Fatalf("repeated policy: %v", err)
	}
	var violation *ConstraintError
	if err := CheckEncodedValue(options, "id", "(0)", "1"); !errors.As(err, &violation) {
		t.Fatalf("disabled replay weakened strict constraints: %v", err)
	}
	// X.690 (02/2021) §8.2.2 admits non-ff TRUE, but an edited typed
	// FALSE must encode as zero. Retained TRUE bytes cannot override it.
	original := []byte{1, 1, 1}
	snapshot := EncodeBoolean(true)
	encoded := EncodeBoolean(false)
	if got := PreserveEncodedBER(encoded, original, snapshot, options); !bytes.Equal(got, []byte{1, 1, 0}) {
		t.Fatalf("edited BOOLEAN = %x", got)
	}
}
