// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/extension_additions_test.go; SHA-256 5d6d8a954fc079acb465d6a0cf04bc3257a4461a97a92ec71d8e58da4a3ce88b.
package aper

import (
	"errors"
	"testing"
)

func TestExtensionBitmapPresenceAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		want error
	}{
		{"present", []byte{1}, nil}, {"empty", []byte{0}, ErrInvalidValue}, {"truncated", nil, ErrTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var additions ExtensionAdditions
			_, _, err := additions.DecodeBitmapAligned(NewBitBufferFromBytes(tc.wire))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestAlignedDecodeSettingsRejectUnsupportedPolicy(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0})
	if err := bb.setDecodeSettingsAligned(decodeSettings{ContainedDecoding: DeferOnError}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("contained policy=%v", err)
	}
}
