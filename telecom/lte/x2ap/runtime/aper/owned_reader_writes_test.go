// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/owned_reader_writes_test.go; SHA-256 5cae09e252b96fb34ee9166696af2fadf7e7e1cdbdd61baf85f98f35749514d8.
package aper

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAttachedReadersCannotExposeOrOverwriteOwnedContents(t *testing.T) {
	for _, owned := range []bool{false, true} {
		for _, size := range []int{1, 65540} {
			for _, operation := range []string{"Bytes", "CompleteBytes", "WriteBit", "WriteBytes"} {
				t.Run(fmt.Sprintf("owned=%t/size=%d/%s", owned, size, operation), func(t *testing.T) {
					payload := bytes.Repeat([]byte{0x20}, size)
					writer := NewBitBuffer()
					if err := EncodeOpenTypeAligned(writer, payload); err != nil {
						t.Fatal(err)
					}
					wire := writer.CompleteBytes()
					parent := NewBitBufferFromBytes(wire)
					if owned {
						var state DecodeState
						wire, state = OwnDecodeOptions(wire)
						parent = NewCompleteDecodeBuffer(wire, state)
						if err := parent.SetDecodeOptionsAligned(state); err != nil {
							t.Fatal(err)
						}
					}
					raw, err := DecodeOpaqueOpenTypeAligned(parent, UnknownSelector, SourceRule{})
					if err != nil {
						t.Fatal(err)
					}
					reader := raw.ChildDecodeBuffer()
					switch operation {
					case "Bytes", "CompleteBytes":
						view := reader.Bytes()
						if operation == "CompleteBytes" {
							view = reader.CompleteBytes()
						}
						if !bytes.Equal(view, payload) {
							t.Fatal("reader byte accessor lost fragmented contents")
						}
						view[0] = 0xff
					case "WriteBit":
						if err := reader.WriteBit(1); err != nil {
							t.Fatal(err)
						}
					case "WriteBytes":
						if err := reader.WriteBytes([]byte{0xff}); err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(raw.Bytes(), payload) {
						t.Fatal("attached reader changed immutable owned contents")
					}
				})
			}
		}
	}
}
