// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/log_interfaces_test.go; SHA-256 b14ab40d2cb922f27e29e2f4000c40bafaab98fb482d10882ed2381e80a82cb3.
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
	if err := reader.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
		t.Fatal(err)
	}
	if !additions.RecoveryEnabled(reader) {
		t.Fatal("explicit recovery option lost")
	}
}
