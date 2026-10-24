// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/sequence_extension_origin_test.go; SHA-256 9a89b39723841845b0f8fff83cdb732f62ceee88a280fc4eba6f1a3fd20799f5.
package aper

import "testing"

func TestSequenceExtensionOwnsOriginSpans(t *testing.T) {
	origin := OpaqueOrigin{Location: Location{Spans: []BitSpan{{Start: 8, End: 16}}, HasWireLocation: true}}
	contents := []byte{0xa5}
	value := NewSequenceExtension(0, contents, origin)
	origin.Location.Spans[0].Start = 0
	contents[0] = 0
	if got := value.Origin().Location.Spans[0]; got != (BitSpan{Start: 8, End: 16}) {
		t.Fatalf("constructor borrowed caller spans: %+v", got)
	}
	returned := value.Origin()
	returned.Location.Spans[0].End = 9
	if got := value.Origin().Location.Spans[0]; got != (BitSpan{Start: 8, End: 16}) {
		t.Fatalf("accessor returned mutable spans: %+v", got)
	}
	if value.Contents()[0] != 0xa5 {
		t.Fatal("constructor borrowed caller contents")
	}
}
