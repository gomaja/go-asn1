// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/log_interfaces_test.go; SHA-256 c627b2b4e6e2009791de7f2c8a64d2fa692c42a1ee26ecf32a13a47ff2024f7e.
package aper

import "testing"

func TestToleranceLogResetPreservesPublishedSnapshot(t *testing.T) {
	log := &ToleranceLog{}
	log.append([]Tolerance{{Path: "Message.Field", Bits: TrailingBits{Bytes: []byte{0x80}, BitLength: 1}}})
	snapshot := log.Snapshot()
	log.Reset()
	if len(log.Snapshot()) != 0 || len(snapshot) != 1 || snapshot[0].Path != "Message.Field" || snapshot[0].Bits.Bytes[0] != 0x80 {
		t.Fatal("reset changed a published snapshot")
	}
	log.append([]Tolerance{{Path: "Message.Other"}})
	if got := log.Snapshot(); len(got) != 1 || got[0].Path != "Message.Other" {
		t.Fatal("reset did not start a fresh log")
	}
}

func TestExtensionRecoveryRequiresExplicitOption(t *testing.T) {
	reader := NewBitBufferFromBytes([]byte{0})
	additions := BeginExtensionAdditions(reader)
	if additions.RecoveryEnabled(reader) {
		t.Fatal("recovery enabled by default")
	}
	if err := reader.setDecodeSettingsAligned(decodeSettings{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	if !additions.RecoveryEnabled(reader) {
		t.Fatal("explicit recovery option lost")
	}
}
