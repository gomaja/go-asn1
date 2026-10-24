// Code generated from UMTS RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/generated_calls_test.go; SHA-256 945bfea75f274d8bdf609c55e7e4d87e9639a6bf0c68984167ac2464e5e42709.
package uper

import (
	"errors"
	"testing"
)

// X.691 (02/2021) §11.2.1 makes an open type a complete encoding.
func TestCompleteOpenTypeValue(t *testing.T) {
	reader := NewBitBufferFromBytes([]byte{0x80})
	if _, err := reader.ReadBit(); err != nil {
		t.Fatal(err)
	}
	value, err := CompleteOpenTypeValue(reader, true)
	if err != nil || !value.Value || !value.PERPadding_.IsZero() {
		t.Fatal(value, err)
	}
	if _, err := CompleteOpenTypeValue(NewBitBufferFromBytes([]byte{0, 0}), false); !errors.Is(err, ErrExtraData) {
		t.Fatal(err)
	}
}

func TestExtensionRecoveryPolicy(t *testing.T) {
	var additions ExtensionAdditions
	if additions.RecoveryEnabled(NewBitBuffer()) {
		t.Fatal("recovery enabled by default")
	}
	var log ToleranceLog
	reader := NewBitBuffer()
	if err := reader.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if !additions.RecoveryEnabled(reader) {
		t.Fatal("explicit recovery option lost")
	}
}

// Generated recovery decoders use these marks to locate a component and its
// collection element. Strict and other tolerance policies leave the path inert.
func TestRecoveryComponentAndIndexPaths(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		var log ToleranceLog
		for _, trailing := range []bool{false, true} {
			reader := NewBitBuffer()
			var options DecodeOptions
			if recovery {
				options.ExtensionRecoveryTolerance = &log
			}
			if trailing {
				options.TrailingBitsTolerance = &log
			}
			if err := reader.SetDecodeOptions(options); err != nil {
				t.Fatal(err)
			}
			component := reader.RecoveryComponent("items")
			index := reader.RecoveryIndex(3)
			if !recovery {
				if component != -1 || index != -1 {
					t.Fatal("disabled recovery changed path")
				}
				if reader.trace != nil && reader.trace.relativePath() != "" {
					t.Fatal("other tolerance acquired recovery path")
				}
				continue
			}
			if component != 0 || index != 1 || reader.trace.relativePath() != "items[3]" {
				t.Fatal("recovery location lost")
			}
			reader.LeaveComponent(index)
			if reader.trace.relativePath() != "items" {
				t.Fatal("index exit lost component")
			}
			reader.LeaveComponent(component)
			if reader.trace.relativePath() != "" {
				t.Fatal("component exit retained path")
			}
		}
	}
}
