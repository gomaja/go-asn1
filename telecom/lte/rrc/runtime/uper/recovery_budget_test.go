// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/recovery_budget_test.go; SHA-256 ba3aa30650b97ccc6a537ee9901874c873ccaa2a1b810b5f9de977f8b5be4a3f.
package uper

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"
	"unsafe"
)

// A rolled-back candidate's first read is free. Re-reading the same bits is
// extra work, and removing the shared limit lets that retry succeed.
func TestRecoveryWorkSurvivesRollback(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		for _, read := range []string{"bits", "bytes", "packed", "alignment"} {
			t.Run(fmt.Sprintf("aligned=%v/%s", aligned, read), func(t *testing.T) {
				var log ToleranceLog
				parent := NewBitBufferFromBytes(nil)
				candidate := []byte{0}
				options := DecodeOptions{ExtensionRecoveryTolerance: &log}

				{
					if err := parent.SetDecodeOptions(options); err != nil {
						t.Fatal(err)
					}
				}
				for attempt := 0; attempt < 2; attempt++ {
					a := ExtensionAdditions{present: []bool{true}}
					decoded, _, err := decodeKnownAddition(&a, parent, 0, candidate, func(child *BitBuffer) error {
						var err error
						switch read {
						case "bits":
							_, err = child.ReadBits(8)
						case "bytes":
							_, err = child.ReadBytes(1)
						case "packed":
							_, err = child.ReadBitsToBytes(8)
						case "alignment":
							_, err = child.ReadBit()
							if err == nil {
								err = child.AlignToOctetRead()
							}
						}
						if err != nil {
							return err
						}
						return fmt.Errorf("unfinished candidate: %w", ErrTruncated)
					})
					if attempt == 0 {
						if err != nil || decoded || !a.Recovered() {
							t.Fatalf("attempt %d: %v %v", attempt, decoded, err)
						}
					} else if !errors.Is(err, ErrResourceLimit) || errors.Is(err, ErrTruncated) || decoded || a.Recovered() {
						t.Fatalf("rollback refunded recovery work: decoded=%v recovered=%v err=%v", decoded, a.Recovered(), err)
					}
				}
				if len(log.Snapshot()) != 0 {
					t.Fatal("failed decode published recoveries")
				}
			})
		}
	}
}

func TestRecoveryWorkCountsOnlyRereadPrefix(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		t.Run(fmt.Sprintf("aligned=%v", aligned), func(t *testing.T) {
			parent := NewBitBufferFromBytes([]byte{0, 0})
			var log ToleranceLog
			options := DecodeOptions{ExtensionRecoveryTolerance: &log}

			{
				if err := parent.SetDecodeOptions(options); err != nil {
					t.Fatal(err)
				}
			}
			data := []byte{0, 0}
			for attempt, bits := range []int{8, 16, 16} {
				a := ExtensionAdditions{present: []bool{true}}
				_, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
					if _, err := child.ReadBits(bits); err != nil {
						return err
					}
					return ErrTruncated
				})
				if err != nil || !a.Recovered() {
					t.Fatalf("attempt %d: %v", attempt, err)
				}
				if want := []uint64{0, 8, 24}[attempt]; parent.trace.work.used != want {
					t.Fatalf("attempt %d charged %d bits, want %d", attempt, parent.trace.work.used, want)
				}
			}
		})
	}
}

func TestRecoveryWorkLinearReread(t *testing.T) {
	for _, size := range []int{64, 1024, 4096} {
		for _, aligned := range []bool{false} {
			_ = aligned
			t.Run(fmt.Sprintf("aligned=%v/size=%d", aligned, size), func(t *testing.T) {
				data := make([]byte, size)
				parent := NewBitBufferFromBytes(make([]byte, size))
				var log ToleranceLog
				options := DecodeOptions{ExtensionRecoveryTolerance: &log}

				{
					if err := parent.SetDecodeOptions(options); err != nil {
						t.Fatal(err)
					}
				}
				for attempt := 0; attempt < 6; attempt++ {
					a := ExtensionAdditions{present: []bool{true}}
					_, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
						if _, err := child.ReadBytes(size); err != nil {
							return err
						}
						return ErrTruncated
					})
					if attempt < 5 && (err != nil || !a.Recovered()) {
						t.Fatalf("attempt %d: %v", attempt, err)
					}
					if attempt == 5 && (!errors.Is(err, ErrResourceLimit) || a.Recovered()) {
						t.Fatalf("attempt %d did not stop at limit: %v", attempt, err)
					}
				}
				if want := uint64(size) * 8 * recoveryWorkInputMultiple; parent.trace.work.used != want {
					t.Fatalf("charged %d bits, want %d", parent.trace.work.used, want)
				}
				if len(log.Snapshot()) != 0 {
					t.Fatal("failed decode published recovery")
				}
			})
		}
	}
}

// Nest ::= SEQUENCE { data OCTET STRING, ...,
//
//	next Nest OPTIONAL, wide INTEGER (0..65535) OPTIONAL, after BOOLEAN OPTIONAL }
//
// Every level carries a one-octet wide addition, short of its required two.
// X.691 (02/2021) 19.8–19.9 and 11.2.1–11.2.2 bound next and wide separately.
func recoveryNestedWire(t *testing.T, aligned bool, depth, size int) []byte {
	t.Helper()
	var next []byte
	for level := 0; level <= depth; level++ {
		b := NewBitBuffer()
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(EncodeBoolean(b, true))

		{
			must(EncodeOctetString(b, bytes.Repeat([]byte{0xa5}, size), 0, 0, false))
		}
		length, open := EncodeNormallySmallLength, EncodeOpenType

		must(length(b, 3))
		must(EncodeBoolean(b, next != nil))
		must(EncodeBoolean(b, true))
		must(EncodeBoolean(b, true))
		if next != nil {
			must(open(b, next))
		}
		must(open(b, []byte{0xa5}))
		must(open(b, []byte{0}))
		next = append([]byte(nil), b.CompleteBytes()...)
	}
	return next
}

func decodeRecoveryNested(b *BitBuffer, aligned bool, attempts *int) error {
	a := BeginExtensionAdditions(b)
	if _, err := DecodeBoolean(b); err != nil {
		return err
	}
	var err error

	{
		_, err = DecodeOctetString(b, 0, 0, false)
	}
	if err != nil {
		return err
	}

	{
		_, _, err = a.DecodeBitmap(b)
	}
	if err != nil {
		return err
	}
	for index, present := range a.present {
		if !present {
			continue
		}
		var data []byte

		{
			data, err = DecodeOpenType(b)
		}
		if err != nil {
			return err
		}
		*attempts++
		_, _, err = decodeKnownAddition(&a, b, int64(index), data, func(child *BitBuffer) error {
			switch index {
			case 0:
				return decodeRecoveryNested(child, aligned, attempts)
			case 1:
				_, err := child.ReadBits(16)
				return err
			default:
				_, err := DecodeBoolean(child)
				return err
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func TestRecoveryNestedWorkLinearBound(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		for _, size := range []int{64, 1024, 4096} {
			for _, depth := range []int{0, 1, 2, 4, 16} {
				t.Run(fmt.Sprintf("aligned=%v/size=%d/depth=%d", aligned, size, depth), func(t *testing.T) {
					wire := recoveryNestedWire(t, aligned, depth, size)
					b := NewBitBufferFromBytes(wire)
					var log ToleranceLog
					if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
						t.Fatal(err)
					}
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					attempts := 0
					err := decodeRecoveryNested(b, aligned, &attempts)
					if err == nil {
						_, err = CaptureFinalBits(b, "Nest")
					}
					runtime.ReadMemStats(&after)
					t.Logf("input=%d examined=%d attempts=%d allocated=%d err=%v", len(wire), b.trace.work.used, attempts, after.TotalAlloc-before.TotalAlloc, err)
					if after.TotalAlloc-before.TotalAlloc > uint64(64*len(wire)+1<<20) {
						t.Fatal("recovery exceeds a linear allocation bound")
					}
					if err != nil || b.trace.work.used != 0 {
						t.Fatalf("first-pass reads were charged: used=%d err=%v", b.trace.work.used, err)
					}
				})
			}
		}
	}
}

func TestRecoveryWorkFatalAndReset(t *testing.T) {
	var log ToleranceLog
	b := NewBitBufferFromBytes([]byte{0})
	if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	site := b.EnterContained()
	site.mode = DeferOnError
	candidate := []byte{0, 0, 0, 0, 0}
	first := ExtensionAdditions{present: []bool{true}}
	_, _, err := decodeKnownAddition(&first, b, 0, candidate, func(child *BitBuffer) error {
		_, _ = child.ReadBits(33)
		return ErrTruncated
	})
	if err != nil || !first.Recovered() {
		t.Fatalf("first pass rejected: %v", err)
	}
	a := ExtensionAdditions{present: []bool{true}}
	_, _, err = decodeKnownAddition(&a, b, 0, candidate, func(child *BitBuffer) error {
		// A callback cannot disguise exhaustion as recoverable truncation.
		_, _ = child.ReadBits(33)
		return ErrTruncated
	})
	if !errors.Is(err, ErrResourceLimit) || a.Recovered() || b.trace.work.active || site.DefersErrors(err) {
		t.Fatalf("fatal limit lost: %v", err)
	}
	if _, err := b.ReadBit(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("limit forgotten after attempt: %v", err)
	}
	if _, err := CaptureFinalBits(b, "Nest"); !errors.Is(err, ErrResourceLimit) || len(log.Snapshot()) != 0 {
		t.Fatalf("limit published: %v", err)
	}
	if _, err := CaptureDeferredBits(b, "Nest"); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("deferred publication lost limit: %v", err)
	}
	if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if b.trace.work != nil && (b.trace.work.used != 0 || b.trace.work.err != nil) {
		t.Fatal("new decode reused old work")
	}
	if _, err := b.ReadBit(); err != nil {
		t.Fatal(err)
	}
	// The budget's widening and multiplication must also fit a 32-bit host.
	b = &BitBuffer{bitLen: math.MaxInt}
	if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	want := uint64(b.bitLen)
	if want > math.MaxUint64/recoveryWorkInputMultiple {
		want = math.MaxUint64
	} else {
		want *= recoveryWorkInputMultiple
	}
	if startRecoveryWork(b).limit != want {
		t.Fatal("input budget overflow")
	}
}

func FuzzRecoveryNestedBudget(f *testing.F) {
	f.Add(uint8(16), uint16(64), false)
	f.Add(uint8(1), uint16(1024), true)
	f.Fuzz(func(t *testing.T, depthByte uint8, sizeWord uint16, aligned bool) {
		depth, size := int(depthByte%33), int(sizeWord%513)
		wire := recoveryNestedWire(t, aligned, depth, size)
		b := NewBitBufferFromBytes(wire)
		var log ToleranceLog
		if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
			t.Fatal(err)
		}
		attempts := 0
		err := decodeRecoveryNested(b, aligned, &attempts)
		if err == nil {
			_, err = CaptureFinalBits(b, "Nest")
		}
		if b.trace.work.used != 0 || err != nil {
			t.Fatalf("unsafe budget outcome: used=%d err=%v", b.trace.work.used, err)
		}
	})
}

func TestRecoveryWorkNestedRollback(t *testing.T) {
	var log ToleranceLog
	b := NewBitBufferFromBytes([]byte{0})
	if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	outerData, innerData := []byte{0}, []byte{0}
	for attempt := 0; attempt < 4; attempt++ {
		outer := ExtensionAdditions{present: []bool{true}}
		_, _, err := decodeKnownAddition(&outer, b, 0, outerData, func(child *BitBuffer) error {
			if _, err := child.ReadBits(8); err != nil {
				return err
			}
			inner := ExtensionAdditions{present: []bool{true}}
			_, _, err := decodeKnownAddition(&inner, child, 0, innerData, func(leaf *BitBuffer) error {
				if _, err := leaf.ReadBits(8); err != nil {
					return err
				}
				return ErrTruncated
			})
			if err != nil {
				return err
			}
			return ErrTruncated
		})
		if attempt < 3 {
			if err != nil || !outer.Recovered() || len(b.trace.pending) != attempt+1 {
				t.Fatalf("nested rollback: %v", err)
			}
		} else if !errors.Is(err, ErrResourceLimit) || outer.Recovered() {
			t.Fatalf("nested rollback refunded work: %v", err)
		}
	}
	if b.trace.work.used != 32 || len(log.Snapshot()) != 0 {
		t.Fatal("nested work or publication changed")
	}
}

func TestRecoveryWorkRejectsCopyBeforeAllocation(t *testing.T) {
	for _, packed := range []bool{false, true} {
		b := NewBitBufferFromBytes(nil)
		if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 1<<20)
		first := ExtensionAdditions{present: []bool{true}}
		_, _, err := decodeKnownAddition(&first, b, 0, data, func(child *BitBuffer) error {
			_, _ = child.ReadBits(8)
			return ErrTruncated
		})
		if err != nil || !first.Recovered() {
			t.Fatalf("first pass rejected: %v", err)
		}
		a := ExtensionAdditions{present: []bool{true}}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, _, err = decodeKnownAddition(&a, b, 0, data, func(child *BitBuffer) error {
			if packed {
				_, err := child.ReadBitsToBytes(len(data) * 8)
				return err
			}
			_, err := child.ReadBytes(len(data))
			return err
		})
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrResourceLimit) || a.Recovered() || after.TotalAlloc-before.TotalAlloc > 32<<10 {
			t.Fatalf("packed=%v over-budget copy allocated: bytes=%d err=%v", packed, after.TotalAlloc-before.TotalAlloc, err)
		}
	}
}

// Root nesting does not create another bounded addition. Re-encoding and
// retaining every recovered enclosing value must still share the budget.
// RootNest ::= SEQUENCE { next RootNest OPTIONAL, ...,
//
//	wide INTEGER (0..65535) OPTIONAL }
func TestRecoveryRootNestingWorkBound(t *testing.T) {
	for _, aligned := range []bool{false} {
		_ = aligned
		for _, count := range []int{2, 64, 256, 1024} {
			t.Run(fmt.Sprintf("aligned=%v/count=%d", aligned, count), func(t *testing.T) {
				wire := NewBitBuffer()
				must := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
				}
				for i := 0; i < count; i++ {
					must(EncodeBoolean(wire, true))
					must(EncodeBoolean(wire, i+1 < count))
				}
				length, open := EncodeNormallySmallLength, EncodeOpenType

				for i := 0; i < count; i++ {
					must(length(wire, 1))
					must(EncodeBoolean(wire, true))
					must(open(wire, []byte{0xa5}))
				}
				b := NewBitBufferFromBytes(wire.CompleteBytes())
				var log ToleranceLog
				if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
					t.Fatal(err)
				}
				states := make([]ExtensionAdditions, count)
				finals := make([]FinalPadding, count)
				for i := range states {
					states[i] = BeginExtensionAdditions(b)
					_, err := b.ReadBits(2)
					must(err)
				}
				var encode func(*BitBuffer, int) error
				encode = func(target *BitBuffer, index int) error {
					start := target.BitPos()
					if err := EncodeBoolean(target, false); err != nil {
						return err
					}
					if err := EncodeBoolean(target, index+1 < count); err != nil {
						return err
					}
					if index+1 < count {
						if err := encode(target, index+1); err != nil {
							return err
						}
					}
					AppendExtensionRecovery(target, finals[index], start)
					return nil
				}
				var err error
				for i := count - 1; i >= 0 && err == nil; i-- {

					{
						_, _, err = states[i].DecodeBitmap(b)
					}
					if err != nil {
						break
					}
					var data []byte

					{
						data, err = DecodeOpenType(b)
					}
					if err != nil {
						break
					}
					_, _, err = decodeKnownAddition(&states[i], b, 0, data, func(child *BitBuffer) error { _, err := child.ReadBits(16); return err })
					if err != nil {
						break
					}
					var expected *BitBuffer
					expected, err = states[i].RecoveryEncoder(b)
					if err == nil {
						err = encode(expected, i)
					}
					if err == nil {
						finals[i], err = states[i].RecordRecovery(b, expected, FinalPadding{})
					}
				}
				t.Logf("input=%d work=%d err=%v", len(wire.Bytes()), b.trace.work.used, err)
				if count == 2 {
					must(err)
					encoded := NewBitBuffer()
					must(encode(encoded, 0))
					if !bytes.Equal(encoded.CompleteBytes(), wire.CompleteBytes()) {
						t.Fatal("root-nested recovery lost exact replay")
					}
				} else if !errors.Is(err, ErrResourceLimit) || b.trace.work.used > uint64(len(wire.Bytes()))*64 {
					t.Fatal("root-nested recovery provenance bypassed the linear work bound")
				}
			})
		}
	}
}

// Complete values must keep the same result, allocation count and bytes when recovery
// is enabled (go-asn1#237). The receiver option's documented extra-work ceiling
// in DecodeOptions.ExtensionRecoveryTolerance leaves all first-pass reads free.
func decodeCompleteRecoveryValue(data []byte, recovery bool) ([2]uint64, DecodeUsage, error) {
	var value [2]uint64
	var usage DecodeUsage
	var accepted, recovered ToleranceLog
	options := DecodeOptions{Usage: &usage, TrailingBitsTolerance: &accepted}
	if recovery {
		options.ExtensionRecoveryTolerance = &recovered
	}
	bb := NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptions(options); err != nil {
		return value, usage, err
	}
	a := BeginExtensionAdditions(bb)
	if _, err := DecodeBoolean(bb); err != nil {
		return value, usage, err
	}
	var err error
	value[0], err = bb.ReadBits(8)
	if err != nil {
		return value, usage, err
	}
	if _, _, err = a.DecodeBitmap(bb); err != nil {
		return value, usage, err
	}
	data, err = DecodeOpenType(bb)
	if err != nil {
		return value, usage, err
	}
	decoded, _, err := decodeKnownAddition(&a, bb, 0, data, func(child *BitBuffer) error {
		value[1], err = child.ReadBits(16)
		return err
	})
	if err != nil {
		return value, usage, err
	}
	if !decoded || a.Recovered() || len(recovered.Snapshot()) != 0 {
		return value, usage, fmt.Errorf("complete addition was recovered")
	}
	_, err = CaptureFinalBits(bb, "Complete")
	return value, usage, err
}

func TestDecodeTraceSize(t *testing.T) {
	t.Logf("decode trace=%d bytes, budget=%d bytes", unsafe.Sizeof(decodeTrace{}), unsafe.Sizeof(DecodeBudget{}))
	// The saved input length must also fit the budget's existing allocation class.
	if size := unsafe.Sizeof(DecodeBudget{}); size > 112 {
		t.Fatalf("decode budget grew beyond the 112-byte allocation class: %d bytes", size)
	}
	if size := unsafe.Sizeof(decodeTrace{}); size > 144 {
		t.Fatalf("decode trace grew beyond the 144-byte allocation class: %d bytes", size)
	}
}

func TestCompleteRecoveryAllocations(t *testing.T) {
	// A complete root byte and one complete two-byte known addition.
	data := []byte{0xd2, 0x80, 0x81, 0x52, 0xad, 0x00}
	var allocations [2]float64
	var allocatedBytes [2]int64
	for i, recovery := range []bool{false, true} {
		got, usage, err := decodeCompleteRecoveryValue(data, recovery)
		if err != nil || got != [2]uint64{0xa5, 0xa55a} || usage.Work != 64 {
			t.Fatalf("recovery=%v: value=%x usage=%+v err=%v", recovery, got, usage, err)
		}
		allocations[i] = testing.AllocsPerRun(100, func() {
			if _, _, err := decodeCompleteRecoveryValue(data, recovery); err != nil {
				t.Fatal(err)
			}
		})

		result := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				if _, _, err := decodeCompleteRecoveryValue(data, recovery); err != nil {
					b.Fatal(err)
				}
			}
		})
		allocatedBytes[i] = result.AllocedBytesPerOp()
	}
	t.Logf("without recovery=%d bytes, with recovery=%d bytes", allocatedBytes[0], allocatedBytes[1])
	if allocatedBytes[0] != allocatedBytes[1] {
		t.Fatalf("complete decode added recovery bytes: without=%d with=%d", allocatedBytes[0], allocatedBytes[1])
	}
	t.Logf("without recovery=%g allocations, with recovery=%g allocations", allocations[0], allocations[1])
	if allocations[1] != allocations[0] {
		t.Fatalf("complete decode added recovery allocations: without=%g with=%g", allocations[0], allocations[1])
	}
}

func BenchmarkCompleteRecoveryDecode(b *testing.B) {
	data := []byte{0xd2, 0x80, 0x81, 0x52, 0xad, 0x00}
	for _, tc := range []struct {
		name     string
		recovery bool
	}{{"without-recovery", false}, {"with-recovery", true}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := decodeCompleteRecoveryValue(data, tc.recovery); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Both scan entry points must activate extra-work accounting even when no
// candidate has rolled back. The fifth eight-bit scan exceeds a 32-bit ceiling.
func TestRecoveryWorkScanWithoutRollback(t *testing.T) {
	for _, scan := range []string{"prefix", "record"} {
		t.Run(scan, func(t *testing.T) {
			bb := NewBitBufferFromBytes([]byte{0xa5})
			var log ToleranceLog
			if err := bb.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
				t.Fatal(err)
			}
			if _, err := bb.ReadBits(8); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 5; attempt++ {
				a := ExtensionAdditions{start: 8, cut: &truncatedExtension{}}
				var err error
				if scan == "prefix" {
					_, err = a.RecoveryEncoder(bb)
				} else {
					expected := NewBitBuffer()
					_, err = a.RecordRecovery(bb, expected, FinalPadding{})
				}
				if attempt < 4 {
					if err != nil || bb.Usage().Work != uint64(16+8*attempt) {
						t.Fatalf("scan %d: work=%d err=%v", attempt, bb.Usage().Work, err)
					}
					continue
				}
				const want = "per: decode resource limit exceeded: extension recovery examined 32 extra bits; next read of 8 extra bits exceeds 4x input budget (32 bits)"
				if !errors.Is(err, ErrResourceLimit) || err.Error() != want || bb.BitPos() != 8 || bb.Usage().Work != 40 {
					t.Fatalf("scan exhaustion: position=%d work=%d err=%v", bb.BitPos(), bb.Usage().Work, err)
				}
				if _, next := bb.ReadBits(0); next != err {
					t.Fatalf("scan exhaustion was not sticky: %v", next)
				}
			}
		})
	}
}

func TestRecoveryWorkExhaustionPosition(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0})
	var log ToleranceLog
	if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	data := []byte{0xa5}
	for attempt := 0; attempt < 6; attempt++ {
		a := ExtensionAdditions{present: []bool{true}}
		position := -1
		decoded, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
			_, err := child.ReadBits(8)
			position = child.BitPos()
			if err != nil {
				return err
			}
			return ErrTruncated
		})
		if attempt < 5 {
			if decoded || err != nil || !a.Recovered() || position != 8 || parent.Usage().Work != uint64(8*(attempt+1)) {
				t.Fatalf("attempt %d: decoded=%v recovered=%v position=%d work=%d err=%v", attempt, decoded, a.Recovered(), position, parent.Usage().Work, err)
			}
			continue
		}
		const want = "per: decode resource limit exceeded: extension recovery examined 32 extra bits; next read of 8 extra bits exceeds 4x input budget (32 bits)"
		if decoded || a.Recovered() || !errors.Is(err, ErrResourceLimit) || err.Error() != want || position != 0 || parent.Usage().Work != 40 {
			t.Fatalf("exhaustion: decoded=%v recovered=%v position=%d work=%d err=%v", decoded, a.Recovered(), position, parent.Usage().Work, err)
		}
		if _, next := parent.ReadBits(0); next != err || len(log.Snapshot()) != 0 {
			t.Fatalf("exhaustion was not sticky or published records: %v", next)
		}
	}
}

func TestRecoveryWorkInheritedInputLimit(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0, 0})
	var log ToleranceLog
	if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	data := []byte{0xa5}
	for attempt := 0; attempt < 10; attempt++ {
		a := ExtensionAdditions{present: []bool{true}}
		_, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
			if _, err := child.ReadBits(8); err != nil {
				return err
			}
			return ErrTruncated
		})
		if attempt < 9 && (err != nil || !a.Recovered()) {
			t.Fatalf("child used its own input length at attempt %d: %v", attempt, err)
		}
		if attempt == 9 && !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("shared top-level ceiling did not exhaust: %v", err)
		}
	}
	if parent.Usage().Work != 72 {
		t.Fatalf("shared work=%d, want 72", parent.Usage().Work)
	}
	if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.ReadBits(16); err != nil || parent.Usage().Work != 16 {
		t.Fatalf("new decode retained exhausted work: %v", err)
	}
}

func TestRecoveryWorkChargesOnlyAbandonedPrefix(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0})
	var log ToleranceLog
	if err := parent.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	abandoned := []byte{0xa5}
	fresh := []byte{0x5a}
	for attempt, data := range [][]byte{abandoned, abandoned, fresh} {
		a := ExtensionAdditions{present: []bool{true}}
		decoded, _, err := decodeKnownAddition(&a, parent, 0, data, func(child *BitBuffer) error {
			if attempt == 0 {
				if _, err := child.ReadBits(4); err != nil {
					return err
				}
				return ErrTruncated
			}
			_, err := child.ReadBits(8)
			return err
		})
		if err != nil || decoded != (attempt != 0) {
			t.Fatalf("attempt %d: decoded=%v err=%v", attempt, decoded, err)
		}
	}
	if _, err := parent.ReadBits(8); err != nil {
		t.Fatal(err)
	}
	if parent.trace.work.used != 4 || parent.Usage().Work != 28 {
		t.Fatalf("charged fresh first-pass bits: extra=%d total=%d", parent.trace.work.used, parent.Usage().Work)
	}
}
