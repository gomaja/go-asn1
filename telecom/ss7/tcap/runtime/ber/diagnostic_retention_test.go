// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/diagnostic_retention_test.go; SHA-256 40a5acbe8a0cbfb327e2312cdf9d8631b7a1747af10f9bab46856acdf4dbcc2a.
package ber

import (
	"bytes"
	asn1runtime "github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"runtime"
	"strings"
	"testing"
	"unsafe"
	"weak"
)

// One malformed child next to a large unrelated OCTET STRING must not pin
// the original allocation through a log, snapshot or retained stage options.
func makeBERDiagnosticRetention(t *testing.T, reports *ViolationLog) (weak.Pointer[[4 << 20]byte], []DecodeOption, []Violation) {
	t.Helper()
	input := new([4 << 20]byte)
	pointer := weak.Make(input)
	outer := len(input) - 5
	input[0], input[1], input[2], input[3], input[4] = 48, 131, byte(outer>>16), byte(outer>>8), byte(outer)
	input[5], input[6], input[7] = 12, 1, 255
	octets := len(input) - 13
	input[8], input[9], input[10], input[11], input[12] = 4, 131, byte(octets>>16), byte(octets>>8), byte(octets)
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(reports)})
	if err := ValidateBERElement(input[:], options...); err != nil {
		t.Fatal(err)
	}
	finish(true)
	snapshot := reports.Snapshot()
	runtime.KeepAlive(input)
	return pointer, options, snapshot
}

func TestBERDiagnosticsDoNotRetainInput(t *testing.T) {
	var reports ViolationLog
	pointer, options, snapshot := makeBERDiagnosticRetention(t, &reports)
	for range 10 {
		runtime.GC()
	}
	if pointer.Value() != nil {
		t.Fatal("one diagnostic retains the 4 MiB input")
	}
	if len(snapshot) != 1 || snapshot[0].ObservedValue != "ff" {
		t.Fatalf("snapshot changed: %+v", snapshot)
	}
	runtime.KeepAlive(&reports)
	runtime.KeepAlive(options)
	runtime.KeepAlive(snapshot)
}

func makeBERExternalRetention(t *testing.T) (weak.Pointer[[4 << 20]byte], asn1runtime.External) {
	t.Helper()
	input := new([4 << 20]byte)
	// A nonminimal EXTERNAL length exercises its unchanged-value snapshot.
	copy(input[:], []byte{40, 129, 8, 6, 2, 42, 3, 129, 2, 65, 66})
	pointer := weak.Make(input)
	decoded, used, err := DecodeExternal(input[:])
	if err != nil || used != 11 {
		t.Fatalf("EXTERNAL: n=%d err=%v", used, err)
	}
	if got, err := EncodeExternal(decoded); err != nil || !bytes.Equal(got, input[:used]) {
		t.Fatalf("replay %x err=%v", got, err)
	}
	runtime.KeepAlive(input)
	return pointer, decoded
}

func TestBERReplaySnapshotDoesNotRetainInput(t *testing.T) {
	pointer, decoded := makeBERExternalRetention(t)
	for range 10 {
		runtime.GC()
	}
	if pointer.Value() != nil {
		t.Fatal("EXTERNAL snapshot retains unrelated input bytes")
	}
	if got := decoded.UnchangedBER(); len(got) != 11 {
		t.Fatalf("replay copied %d bytes", len(got))
	}
	runtime.KeepAlive(decoded)
}

func makeBERObservedRetention(t *testing.T, reports *ViolationLog) (weak.Pointer[byte], []DecodeOption) {
	t.Helper()
	observation := strings.Repeat("x", 4<<20)
	pointer := weak.Make(unsafe.StringData(observation))
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(reports)})
	if err := CheckDecodedValue(options, "text", "(0)", observation); err != nil {
		t.Fatal(err)
	}
	finish(true)
	runtime.KeepAlive(observation)
	return pointer, options
}

func TestBERObservedValueDoesNotRetainInput(t *testing.T) {
	var reports ViolationLog
	pointer, options := makeBERObservedRetention(t, &reports)
	for range 10 {
		runtime.GC()
	}
	if pointer.Value() != nil {
		t.Fatal("bounded observation retains its 4 MiB backing allocation")
	}
	if got := reports.Snapshot(); len(got) != 1 || len(got[0].ObservedValue) != MaxObservedValueBytes || got[0].ObservedValueLength != 4<<20 {
		t.Fatal("bounded observation changed")
	}
	runtime.KeepAlive(&reports)
	runtime.KeepAlive(options)
}
