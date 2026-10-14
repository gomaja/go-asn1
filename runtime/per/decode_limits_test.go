package per

import (
	"errors"
	"math"
	"testing"
)

func TestDecodeLimitsValidation(t *testing.T) {
	for _, change := range []func(*DecodeLimits){
		func(l *DecodeLimits) { l.MaxDepth = -1 },
		func(l *DecodeLimits) { l.MaxElements = -1 },
		func(l *DecodeLimits) { l.MaxOpenTypeDepth = -1 },
		func(l *DecodeLimits) { l.MaxWork = -1 },
	} {
		var limits DecodeLimits
		change(&limits)
		if err := ValidateDecodeOptions(DecodeOptions{Limits: limits}); !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("invalid limits %+v: %v", limits, err)
		}
	}
	if err := ValidateDecodeOptions(DecodeOptions{Limits: DecodeLimits{}}); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []DecodeLimits{{MaxDepth: math.MaxInt}, {MaxElements: math.MaxInt}, {MaxOpenTypeDepth: math.MaxInt}, {MaxWork: math.MaxInt}} {
		if err := ValidateDecodeOptions(DecodeOptions{Limits: limit}); err != nil {
			t.Fatalf("large positive limit %+v: %v", limit, err)
		}
	}
}

func TestDecodeLimitsBoundaries(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		bb := NewBitBufferFromBytes([]byte{0xff, 0xff})
		options := DecodeOptions{Limits: DecodeLimits{MaxDepth: 2, MaxElements: 3, MaxOpenTypeDepth: 1, MaxWork: 8}}
		var err error
		if aligned {
			err = bb.SetDecodeOptionsAligned(options)
		} else {
			err = bb.SetDecodeOptions(options)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := bb.EnterDecodeValue(); err != nil {
			t.Fatal(err)
		}
		if err := bb.EnterDecodeValue(); err != nil {
			t.Fatal(err)
		}
		if err := bb.EnterDecodeValue(); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("depth: %v", err)
		}
		bb.LeaveDecodeValue()
		bb.LeaveDecodeValue()

		bb = NewBitBufferFromBytes([]byte{0xff, 0xff})
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		if err := bb.ChargeElements(3); err != nil {
			t.Fatal(err)
		}
		if err := bb.ChargeElements(1); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("elements: %v", err)
		}

		bb = NewBitBufferFromBytes([]byte{0xff, 0xff})
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		first := NewBitBufferFromBytes([]byte{0xff})
		if err := first.InheritOpenTypeDecodeOptions(bb); err != nil {
			t.Fatal(err)
		}
		second := NewBitBufferFromBytes([]byte{0xff})
		if err := second.InheritOpenTypeDecodeOptions(first); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("open type: %v", err)
		}
		if _, err := first.ReadBit(); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("open-type failure did not remain fatal: %v", err)
		}

		bb = NewBitBufferFromBytes([]byte{0xff, 0xff})
		if err := bb.SetDecodeOptions(options); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBits(8); err != nil {
			t.Fatal(err)
		}
		if _, err := bb.ReadBit(); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("work: %v", err)
		}
	}
}

func TestDecodeBudgetSharedAcrossSiblings(t *testing.T) {
	parent := NewBitBufferFromBytes([]byte{0xff})
	var usage DecodeUsage
	if err := parent.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxElements: 2, MaxWork: 16}, Usage: &usage}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		child := NewBitBufferFromBytes([]byte{0xff})
		child.InheritDecodeOptions(parent)
		if err := child.ChargeElements(1); err != nil {
			t.Fatal(err)
		}
		if _, err := child.ReadBits(8); err != nil {
			t.Fatal(err)
		}
	}
	if usage.Elements != 2 || usage.Work != 16 {
		t.Fatalf("committed usage = %+v", usage)
	}
	child := NewBitBufferFromBytes([]byte{0xff})
	child.InheritDecodeOptions(parent)
	if _, err := child.ReadBit(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("sibling exceeded work limit: %v", err)
	}
	if _, err := parent.ReadBit(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("parent resumed after resource limit: %v", err)
	}
}

func TestDecodeCollectionFragmentElementLimit(t *testing.T) {
	// ITU-T X.691 (02/2021) §11.9.3.8 interleaves a 16K fragment and
	// the trailing length determinant. Both counts share one budget.
	const count = 16*1024 + 1
	for _, aligned := range []bool{false, true} {
		writer := NewBitBuffer()
		if err := EncodeCollection(writer, count, SizeConstraint{}, aligned, func(_, n int64) error {
			for range n {
				if err := writer.WriteBit(1); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		wire := writer.CompleteBytes()
		if len(wire) != 2051 || wire[0] != 0xc1 || wire[2049] != 0x01 || wire[2050] != 0x80 {
			t.Fatalf("aligned=%v: incorrect X.691 §11.9.3.8 fragment framing", aligned)
		}
		for _, limit := range []int{count - 1, count} {
			reader := NewBitBufferFromBytes(wire)
			if err := reader.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxElements: limit}}); err != nil {
				t.Fatal(err)
			}
			_, err := DecodeCollection(reader, SizeConstraint{}, aligned, func(_, n int64) error {
				for range n {
					if _, err := reader.ReadBit(); err != nil {
						return err
					}
				}
				return nil
			})
			if limit == count && err != nil {
				t.Fatalf("aligned=%v exact limit: %v", aligned, err)
			}
			if limit == count-1 && !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("aligned=%v limit+1: %v", aligned, err)
			}
		}
	}
}

func TestDecodeWorkIsLinearInInput(t *testing.T) {
	for _, n := range []int{128, 1024, 8192, 65536} {
		wire := make([]byte, n)
		reader := NewBitBufferFromBytes(wire)
		var usage DecodeUsage
		if err := reader.SetDecodeOptions(DecodeOptions{Usage: &usage}); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadBytes(n); err != nil {
			t.Fatal(err)
		}
		if usage.Work != uint64(n)*8 {
			t.Fatalf("n=%d examined %d bits", n, usage.Work)
		}
		if _, err := reader.ReadBit(); !errors.Is(err, ErrTruncated) {
			t.Fatalf("n=%d end: %v", n, err)
		}
		if reader.Usage().Work != usage.Work {
			t.Fatal("metrics diverged")
		}
	}
	reader := NewBitBufferFromBytes([]byte{0xff})
	if err := reader.SetDecodeOptions(DecodeOptions{}); err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		reader.bitPos = 0
		if _, err := reader.ReadBit(); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("common-path accounting allocated %v objects per bit", allocations)
	}
}

// The bulk reader must examine exactly the same bits as the single-bit
// oracle, including prefixes of truncated reads and unaligned 64-bit fields.
func TestBulkReadBitsMatchesBitOracle(t *testing.T) {
	for size := 0; size <= 10; size++ {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*37 + 19)
		}
		for offset := 0; offset < 8; offset++ {
			for width := 0; width <= 64; width++ {
				var budget DecodeBudget
				fast := NewDecodeBuffer(data, &budget)
				slow := NewBitBufferFromBytes(data)
				fast.bitPos, slow.bitPos = offset, offset
				got, err := fast.ReadBits(width)
				var want uint64
				var wantErr error
				for range width {
					bit, e := slow.ReadBit()
					if e != nil {
						want, wantErr = 0, e
						break
					}
					want = want<<1 | uint64(bit)
				}
				if got != want || !errors.Is(err, wantErr) || fast.bitPos != slow.bitPos || fast.Usage().Work != slow.Usage().Work {
					t.Fatalf("size=%d offset=%d width=%d: %x/%v/%d/%d want %x/%v/%d/%d", size, offset, width, got, err, fast.bitPos, fast.Usage().Work, want, wantErr, slow.bitPos, slow.Usage().Work)
				}
			}
		}
	}
}

func TestSharedDecodeBudgetClosesOpenTypeScopes(t *testing.T) {
	var budget DecodeBudget
	parent := NewDecodeBuffer([]byte{0xff}, &budget)
	if err := parent.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxOpenTypeDepth: 1, MaxWork: 16}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		child := NewBitBufferFromBytes([]byte{0xff})
		if err := child.InheritOpenTypeDecodeOptions(parent); err != nil {
			t.Fatal(err)
		}
		if child.budget != parent.budget {
			t.Fatal("child did not inherit budget pointer")
		}
		if _, err := child.ReadBits(8); err != nil {
			t.Fatal(err)
		}
		child.LeaveOpenType()
	}
	if parent.Usage().Work != 16 || budget.openDepth != 0 {
		t.Fatalf("unbalanced sibling scopes: %+v", parent.Usage())
	}
	if _, err := parent.ReadBit(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("parent forgot child work: %v", err)
	}
}

func FuzzBulkPERReadBudget(f *testing.F) {
	f.Add([]byte{0x19, 0xa5, 0xff}, uint8(3), uint8(17), uint8(16))
	f.Add([]byte{0xff}, uint8(0), uint8(8), uint8(8))
	f.Fuzz(func(t *testing.T, data []byte, offsetByte, widthByte, limitByte uint8) {
		if len(data) > 128 {
			t.Skip()
		}
		offset, width, limit := int(offsetByte%8), int(widthByte%65), int(limitByte)+1
		var budget DecodeBudget
		bb := NewDecodeBuffer(data, &budget)
		if err := bb.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxWork: limit}}); err != nil {
			t.Fatal(err)
		}
		bb.bitPos = offset
		_, err := bb.ReadBits(width)
		if bb.Usage().Work > uint64(limit) {
			t.Fatal("read exceeded work budget")
		}
		if errors.Is(err, ErrResourceLimit) {
			if _, err := bb.ReadBits(0); !errors.Is(err, ErrResourceLimit) {
				t.Fatal("limit error was not sticky")
			}
		}
	})
}

func TestRecoveryProvenanceSharesGeneralWorkBudget(t *testing.T) {
	for _, limit := range []int{19, 20} {
		var budget DecodeBudget
		parent := NewDecodeBuffer([]byte{0xa5}, &budget)
		var log ToleranceLog
		if err := parent.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxWork: limit}, ExtensionRecoveryTolerance: &log}); err != nil {
			t.Fatal(err)
		}
		if _, err := parent.ReadBits(8); err != nil {
			t.Fatal(err)
		}
		expected := NewBitBuffer()
		if err := expected.WriteBits(0, 4); err != nil {
			t.Fatal(err)
		}
		state := ExtensionAdditions{recovered: true}
		_, err := state.RecordRecovery(parent, expected, FinalPadding{})
		if limit == 19 && !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("typed provenance scan escaped general budget: %v", err)
		}
		if limit == 20 && (err != nil || parent.Usage().Work != 20) {
			t.Fatalf("exact provenance limit: work=%d err=%v", parent.Usage().Work, err)
		}
		if len(log.Snapshot()) != 0 {
			t.Fatal("resource failure published tolerance records")
		}
	}
}

func TestCutProvenanceSharesGeneralWorkBudget(t *testing.T) {
	for _, limit := range []int{29, 30} {
		var budget DecodeBudget
		parent := NewDecodeBuffer([]byte{0xb5, 0x5b, 0xf0, 0x0f, 0x3c, 0xc3}, &budget)
		if err := parent.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxWork: limit}}); err != nil {
			t.Fatal(err)
		}
		reader := *parent
		state := ExtensionAdditions{start: 3, root: 5, bitmap: 12, end: 16, present: []bool{true, false, true, true}}
		_, err := state.cutRecord(&reader, parent.data, 2, 30, true)
		if limit == 29 && !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("cut provenance escaped general budget: %v", err)
		}
		if limit == 30 && (err != nil || parent.Usage().Work != 30) {
			t.Fatalf("exact cut limit: work=%d err=%v", parent.Usage().Work, err)
		}
	}
}

func TestRaisedWorkLimitValueKeepsEncodingReplay(t *testing.T) {
	// A received value may exceed the default work ceiling when the caller
	// raises it. Comparing its retained typed encoding during encode must not
	// impose the receiver default again and discard the received provenance.
	bits := DefaultDecodeLimits().MaxWork + 8
	data := make([]byte, bits/8)
	writer := &BitBuffer{data: data, bitPos: bits}
	kept := truncatedExtension{recovered: true, expected: data, expectedBits: bits}
	if !kept.follows(writer) {
		t.Fatal("encoding comparison discarded a large unchanged value")
	}
}

func TestOpaqueOpenTypeDepthBoundaries(t *testing.T) {
	// X.691 (02/2021) §§11.2.1–11.2.2: a frame inside an already
	// decoded open type adds one level even if its actual type is opaque.
	for _, aligned := range []bool{false, true} {
		writer := NewBitBuffer()
		encode, decode := EncodeOpenType, DecodeOpenType
		if aligned {
			encode, decode = EncodeOpenTypeAligned, DecodeOpenTypeAligned
		}
		if err := encode(writer, []byte{0}); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{1, 2} {
			var budget DecodeBudget
			reader := NewDecodeBuffer(writer.Bytes(), &budget)
			if err := reader.SetDecodeOptions(DecodeOptions{Limits: DecodeLimits{MaxOpenTypeDepth: limit}}); err != nil {
				t.Fatal(err)
			}
			if err := reader.EnterOpenType(); err != nil {
				t.Fatal(err)
			}
			_, err := decode(reader)
			reader.LeaveOpenType()
			if limit == 1 && !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("aligned=%v opaque nesting exceeded by one: %v", aligned, err)
			}
			if limit == 2 && (err != nil || reader.Usage().MaxOpenTypeDepth != 2 || budget.openDepth != 0) {
				t.Fatalf("aligned=%v exact opaque nesting: usage=%+v err=%v", aligned, reader.Usage(), err)
			}
		}
	}
}
