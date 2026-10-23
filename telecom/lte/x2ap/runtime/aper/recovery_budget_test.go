// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/recovery_budget_test.go; SHA-256 c41a0bbc479456db35b1622ce61d7639f671de692704ca13d3d871974db233fb.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

// A rolled-back candidate's first read is free. Re-reading the same bits is
// extra work, and removing the shared limit lets that retry succeed.
func TestRecoveryWorkSurvivesRollback(t *testing.T) {
	for _, aligned := range []bool{true} {
		for _, read := range []string{"bits", "bytes", "packed", "alignment"} {
			t.Run(fmt.Sprintf("aligned=%v/%s", aligned, read), func(t *testing.T) {
				var log ToleranceLog
				parent := NewBitBufferFromBytes(nil)
				candidate := []byte{0}
				options := DecodeOptions{ExtensionRecoveryTolerance: &log}
				if aligned {
					if err := parent.SetDecodeOptionsAligned(options); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := parent.SetDecodeOptionsAligned(options); err != nil {
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
	for _, aligned := range []bool{true} {
		t.Run(fmt.Sprintf("aligned=%v", aligned), func(t *testing.T) {
			parent := NewBitBufferFromBytes([]byte{0, 0})
			var log ToleranceLog
			options := DecodeOptions{ExtensionRecoveryTolerance: &log}
			if aligned {
				if err := parent.SetDecodeOptionsAligned(options); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := parent.SetDecodeOptionsAligned(options); err != nil {
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
		for _, aligned := range []bool{true} {
			t.Run(fmt.Sprintf("aligned=%v/size=%d", aligned, size), func(t *testing.T) {
				data := make([]byte, size)
				parent := NewBitBufferFromBytes(make([]byte, size))
				var log ToleranceLog
				options := DecodeOptions{ExtensionRecoveryTolerance: &log}
				if aligned {
					if err := parent.SetDecodeOptionsAligned(options); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := parent.SetDecodeOptionsAligned(options); err != nil {
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
		if aligned {
			must(EncodeOctetStringAligned(b, bytes.Repeat([]byte{0xa5}, size), 0, 0, false))
		} else {
			must(EncodeOctetStringAligned(b, bytes.Repeat([]byte{0xa5}, size), 0, 0, false))
		}
		length, open := EncodeNormallySmallLengthAligned, EncodeOpenTypeAligned
		if aligned {
			length, open = EncodeNormallySmallLengthAligned, EncodeOpenTypeAligned
		}
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
	if aligned {
		_, err = DecodeOctetStringAligned(b, 0, 0, false)
	} else {
		_, err = DecodeOctetStringAligned(b, 0, 0, false)
	}
	if err != nil {
		return err
	}
	if aligned {
		_, _, err = a.DecodeBitmapAligned(b)
	} else {
		_, _, err = a.DecodeBitmapAligned(b)
	}
	if err != nil {
		return err
	}
	for index, present := range a.present {
		if !present {
			continue
		}
		var data []byte
		if aligned {
			data, err = DecodeOpenTypeAligned(b)
		} else {
			data, err = DecodeOpenTypeAligned(b)
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
	for _, aligned := range []bool{true} {
		for _, size := range []int{64, 1024, 4096} {
			for _, depth := range []int{0, 1, 2, 4, 16} {
				t.Run(fmt.Sprintf("aligned=%v/size=%d/depth=%d", aligned, size, depth), func(t *testing.T) {
					wire := recoveryNestedWire(t, aligned, depth, size)
					b := NewBitBufferFromBytes(wire)
					var log ToleranceLog
					if err := b.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
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

func TestRecoveryWorkNestedRollback(t *testing.T) {
	var log ToleranceLog
	b := NewBitBufferFromBytes([]byte{0})
	if err := b.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
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
		if err := b.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
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
	for _, aligned := range []bool{true} {
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
				length, open := EncodeNormallySmallLengthAligned, EncodeOpenTypeAligned
				if aligned {
					length, open = EncodeNormallySmallLengthAligned, EncodeOpenTypeAligned
				}
				for i := 0; i < count; i++ {
					must(length(wire, 1))
					must(EncodeBoolean(wire, true))
					must(open(wire, []byte{0xa5}))
				}
				b := NewBitBufferFromBytes(wire.CompleteBytes())
				var log ToleranceLog
				if err := b.SetDecodeOptionsAligned(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
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
					if aligned {
						_, _, err = states[i].DecodeBitmapAligned(b)
					} else {
						_, _, err = states[i].DecodeBitmapAligned(b)
					}
					if err != nil {
						break
					}
					var data []byte
					if aligned {
						data, err = DecodeOpenTypeAligned(b)
					} else {
						data, err = DecodeOpenTypeAligned(b)
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
