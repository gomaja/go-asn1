// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_parts_depth_test.go; SHA-256 b08765530676296cbc3dd1db72273f076815105177644c4ffe3fdc85a685e44f.
package ber

import (
	"bytes"
	"testing"
)

// A caller may raise DecodeLimits.MaxDepth; the replay walk over a received
// encoding stops at maxReplayPartDepth so that a deep value falls back to a
// canonical rebuild instead of exhausting the goroutine stack.
func TestReplayPartDepthIsBounded(t *testing.T) {
	nested := func(depth int) []byte {
		data := bytes.Repeat([]byte{0x30, 0x80}, depth)
		data = append(data, 0x05, 0x00)
		return append(data, bytes.Repeat([]byte{0x00, 0x00}, depth)...)
	}
	if replayPartRoot(nested(maxReplayPartDepth)) == nil {
		t.Fatal("a value at the depth bound was not walked")
	}
	if replayPartRoot(nested(maxReplayPartDepth+1)) != nil {
		t.Fatal("a value deeper than the bound was walked")
	}
}
