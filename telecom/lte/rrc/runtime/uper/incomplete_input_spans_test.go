// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/incomplete_input_spans_test.go; SHA-256 d29f466259551099e6808ebdcb5f95bc923b98bc0e8589aa0bf92b231a18a663.
package uper

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

func decodeIncompleteSpanAddition(t *testing.T, bb *BitBuffer) {
	t.Helper()
	a := ExtensionAdditions{present: []bool{true}}
	if !a.Received(bb, 0) {
		t.Fatal("addition not received")
	}
	raw, err := DecodeOpenType(bb)
	if err != nil {
		t.Fatal(err)
	}
	if !a.RecoveryEnabled(bb) {
		t.Fatal("recovery not enabled")
	}
	child := NewNestedDecodeBuffer(raw, bb)
	if err := child.EnterOpenType(); err != nil {
		t.Fatal(err)
	}
	checkpoint := child.CheckpointKnownAddition()
	if _, err := child.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	_, failure := child.ReadBit()
	decoded, _, err := a.CompleteKnownAddition(child, 0, raw, checkpoint, failure, false)
	if err != nil || decoded {
		t.Fatalf("recovery=%v %v", decoded, err)
	}
}

func TestIncompleteExtensionInputSpans(t *testing.T) {
	for _, mode := range []string{"top", "open", "octets", "bits", "fragmented", "detached"} {
		for _, positions := range []string{"disabled", "enabled", "padding"} {
			t.Run(mode+"/"+positions, func(t *testing.T) {
				prefix := 3
				if mode == "fragmented" {
					prefix = perFragmentUnit*8 - 12
				}
				payload := NewBitBuffer()
				if err := payload.WriteBitsFromBytes(make([]byte, (prefix+7)/8), prefix); err != nil {
					t.Fatal(err)
				}
				if err := EncodeOpenType(payload, []byte{0xa5}); err != nil {
					t.Fatal(err)
				}
				wire := payload.CompleteBytes()
				want := []InputBitSpan{{Offset: prefix, BitLength: 16}}
				var log, paddingLog ToleranceLog
				options := DecodeOptions{ExtensionRecoveryTolerance: &log}
				if positions == "padding" {
					options.PaddingObservations = &paddingLog
				}
				if positions == "enabled" {
					setInputSpanOption(t, &options)
				}
				var bb, top *BitBuffer
				if mode == "top" {
					top = NewBitBufferFromBytes(wire)
					if err := top.SetDecodeOptions(options); err != nil {
						t.Fatal(err)
					}
					bb = top
				} else {
					outer := NewBitBuffer()
					if err := outer.WriteBits(5, 3); err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "bits":
						if err := EncodeBitString(outer, payload.Bytes(), payload.BitsWritten(), 0, 0, false); err != nil {
							t.Fatal(err)
						}
					case "octets":
						if err := EncodeOctetString(outer, wire, 0, 0, false); err != nil {
							t.Fatal(err)
						}
					default:
						if err := EncodeOpenType(outer, wire); err != nil {
							t.Fatal(err)
						}
					}
					top = NewBitBufferFromBytes(outer.CompleteBytes())
					if err := top.SetDecodeOptions(options); err != nil {
						t.Fatal(err)
					}
					if _, err := top.ReadBits(3); err != nil {
						t.Fatal(err)
					}
					var raw []byte
					var bitLength int
					var err error
					switch mode {
					case "bits":
						raw, bitLength, err = DecodeBitString(top, 0, 0, false)
					case "octets":
						raw, err = DecodeOctetString(top, 0, 0, false)
					default:
						raw, err = DecodeOpenType(top)
					}
					if err != nil {
						t.Fatal(err)
					}
					if mode == "detached" {
						raw = bytes.Clone(raw)
					}
					bb = NewNestedDecodeBuffer(raw, top)
					if mode == "bits" {
						if err := bb.SetReadBitLength(bitLength); err != nil {
							t.Fatal(err)
						}
					}
					want = []InputBitSpan{{Offset: 11 + prefix, BitLength: 16}}
					if mode == "fragmented" {
						want = []InputBitSpan{{Offset: 11 + prefix, BitLength: 12}, {Offset: 11 + prefix + 20, BitLength: 4}}
					}
					if mode == "detached" {
						want = nil
					}
					wire = outer.Bytes()
				}
				if positions == "disabled" {
					want = nil
				}
				if _, err := bb.ReadBitsToBytes(prefix); err != nil {
					t.Fatal(err)
				}
				decodeIncompleteSpanAddition(t, bb)
				top.commitRecords("Synthetic")
				records := log.Snapshot()
				if len(records) != 1 {
					t.Fatalf("records=%+v", records)
				}
				r := records[0]
				if r.Offset != prefix || r.Kind != ToleratedIncompleteExtension || r.DeclaredLength != 1 || r.ConsumedBits != 8 || r.Path != "Synthetic.ExtData_[0]" || !errors.Is(r.Err, ErrTruncated) {
					t.Fatalf("record=%+v", r)
				}
				if !reflect.DeepEqual(r.InputSpans, want) {
					t.Fatalf("spans=%+v want %+v", r.InputSpans, want)
				}
				var actual []byte
				for _, span := range r.InputSpans {
					for bit := span.Offset; bit < span.Offset+span.BitLength; bit++ {
						actual = append(actual, (wire[bit/8]>>uint(7-bit%8))&1)
					}
				}
				if mode != "detached" && positions != "disabled" {
					expected := []byte{0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1}
					if !bytes.Equal(actual, expected) {
						t.Fatalf("span bits=%v want %v", actual, expected)
					}
				}
			})
		}
	}
}

func TestIncompleteExtensionStateSizes(t *testing.T) {
	t.Logf("decodeTrace=%d BitBuffer=%d", unsafe.Sizeof(decodeTrace{}), unsafe.Sizeof(BitBuffer{}))
	if unsafe.Sizeof(decodeTrace{}) > 144 || unsafe.Sizeof(BitBuffer{}) > 64 {
		t.Fatal("state size limit exceeded")
	}
}

func setInputSpanOption(t *testing.T, options *DecodeOptions) {
	t.Helper()
	options.InputSpans = true
}

func TestInputSpansRequiresPaddingLog(t *testing.T) {
	var unrelated ToleranceLog
	bb := NewBitBufferFromBytes([]byte{0x05})
	options := DecodeOptions{TrailingBitsTolerance: &unrelated}
	setInputSpanOption(t, &options)
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Value"); err != nil {
		t.Fatal(err)
	}
	if len(unrelated.Snapshot()) != 0 {
		t.Fatal("padding published without its log")
	}
}

func TestIncompleteAndCutAdditionRecords(t *testing.T) {
	// The same known addition: its complete open type contains one octet,
	// but decoding the known value requires two. Removing the last input
	// octet cuts that open type instead; its existing record stays unchanged.
	wire, starts := encodeHolderAt(t, &holder{flag: true, present: []bool{true}, data: [][]byte{{0xa5}}}, false)
	for _, positions := range []bool{false, true} {
		var incomplete, cuts ToleranceLog
		options := DecodeOptions{ExtensionRecoveryTolerance: &incomplete, TruncatedExtensionTolerance: &cuts}
		if positions {
			setInputSpanOption(t, &options)
		}
		bb := NewBitBufferFromBytes(wire)
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(starts[0]); err != nil {
			t.Fatal(err)
		}
		decodeIncompleteSpanAddition(t, bb)
		bb.commitRecords("Synthetic")
		records := incomplete.Snapshot()
		if len(records) != 1 || records[0].Offset != starts[0] || len(cuts.Snapshot()) != 0 {
			t.Fatalf("incomplete=%+v cut=%+v", records, cuts.Snapshot())
		}
		if positions && !reflect.DeepEqual(records[0].InputSpans, []InputBitSpan{{Offset: starts[0], BitLength: 16}}) {
			t.Fatalf("spans=%+v", records[0].InputSpans)
		}
		if !positions && len(records[0].InputSpans) != 0 {
			t.Fatal("unrequested spans")
		}
		incomplete.Reset()
		if _, err := decodeTop(wire[:len(wire)-1], 0, false, options); err != nil {
			t.Fatal(err)
		}
		cut := cuts.Snapshot()
		if len(cut) != 1 || cut[0].Kind != ToleratedTruncatedExtension || cut[0].Offset != starts[0] || len(cut[0].InputSpans) != 0 || len(incomplete.Snapshot()) != 0 {
			t.Fatalf("cut=%+v incomplete=%+v", cut, incomplete.Snapshot())
		}
	}
}

// Source metadata and emitted diagnostics must grow with the number of
// additions, rather than copying the enclosing input for every record.
func TestIncompleteInputMappingLinearCost(t *testing.T) {
	for _, count := range []int{256, 1024, 4096} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			wire := bytes.Repeat([]byte{1, 0xa5}, count)
			bb := NewBitBufferFromBytes(wire)
			var log ToleranceLog
			if err := bb.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log, InputSpans: true}); err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range count {
				decodeIncompleteSpanAddition(t, bb)
			}
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			allocations := after.Mallocs - before.Mallocs
			t.Logf("additions=%d bytes=%d allocations=%d", count, allocated, allocations)
			if allocated > uint64(4096*count+1<<20) || allocations > uint64(32*count+1024) {
				t.Fatal("input mapping exceeds linear allocation bound")
			}
			if len(bb.trace.pending) != count {
				t.Fatalf("records=%d", len(bb.trace.pending))
			}
			for i, record := range bb.trace.pending {
				if !reflect.DeepEqual(record.InputSpans, []InputBitSpan{{Offset: 16 * i, BitLength: 16}}) {
					t.Fatalf("addition %d spans=%+v", i, record.InputSpans)
				}
			}
		})
	}
}
