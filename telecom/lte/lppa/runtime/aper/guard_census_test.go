// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/guard_census_test.go; SHA-256 c1899db38c0da682c0339f0e8791d8c7608b8dcbc3f829432827f89d6987af03.
package aper

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestCensusIntegerValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func() error
		want error
		text string
	}{
		{"semi below lower", func() error { return EncodeSemiConstrainedWholeNumberAligned(NewBitBuffer(), 1, 2) }, ErrConstraintViolation, ""},
		{"semi zero length", func() error {
			_, e := DecodeSemiConstrainedWholeNumberAligned(NewBitBufferFromBytes([]byte{0}), 0)
			return e
		}, ErrInvalidValue, "zero-length semi-constrained"},
		{"semi nine octets", func() error {
			_, e := DecodeSemiConstrainedWholeNumberAligned(NewBitBufferFromBytes(append([]byte{9}, bytes.Repeat([]byte{1}, 9)...)), 0)
			return e
		}, ErrLimit, "maximum is 8"},
		{"long constrained unused code", func() error {
			_, e := DecodeConstrainedWholeNumberAligned(NewBitBufferFromBytes([]byte{0x80, 1, 0x86, 0xa1}), 0, 100000)
			return e
		}, ErrInvalidValue, ""},
		{"long normally small length", func() error {
			_, e := DecodeNormallySmallLengthAligned(NewBitBufferFromBytes([]byte{0x80, 1}))
			return e
		}, ErrInvalidValue, "not greater than 64"},
		{"raw reversed encode", func() error { return EncodeConstrainedWholeNumber(NewBitBuffer(), 0, 1, 0) }, ErrInvalidValue, ""},
		{"raw outside encode", func() error { return EncodeConstrainedWholeNumber(NewBitBuffer(), 3, 0, 2) }, ErrConstraintViolation, ""},
		{"raw reversed decode", func() error { _, e := DecodeConstrainedWholeNumber(NewBitBufferFromBytes(nil), 1, 0); return e }, ErrInvalidValue, ""},
		{"raw unused code", func() error {
			_, e := DecodeConstrainedWholeNumber(NewBitBufferFromBytes([]byte{0xc0}), 0, 2)
			return e
		}, ErrInvalidValue, ""},
		{"raw negative length", func() error { return EncodeUnconstrainedLength(NewBitBuffer(), -1) }, ErrInvalidValue, "negative length"},
		{"raw fragment length", func() error { _, e := DecodeUnconstrainedLength(NewBitBufferFromBytes([]byte{0xc1})); return e }, ErrInvalidValue, "interleaved"},
		{"negative extension root", func() error { _, e := addExtensionIndex(-1, 1); return e }, ErrInvalidValue, ""},
		{"negative extension index", func() error { _, e := addExtensionIndex(1, -1); return e }, ErrInvalidValue, ""},
		{"root size", func() error { return validateRootSize(3, 0, 2, true) }, ErrConstraintViolation, ""},
		{"extension size", func() error { return rejectRootLengthInExtension("BIT STRING", 1, 0, 2) }, ErrInvalidValue, "inside the root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("guard: %v, want %v containing %q", err, tc.want, tc.text)
			}
		})
	}
	if _, _, e := decodeExtensionBitmapBits(&BitBuffer{bitPos: 8}, 0); !errors.Is(e, ErrInvalidValue) {
		t.Fatalf("negative bitmap remainder: %v", e)
	}
	for _, value := range []int64{0, 256, math.MaxInt64} {
		w := NewBitBuffer()
		if e := EncodeSemiConstrainedWholeNumberAligned(w, value, math.MinInt64); e != nil {
			t.Fatal(e)
		}
		got, e := DecodeSemiConstrainedWholeNumberAligned(NewBitBufferFromBytes(w.Bytes()), math.MinInt64)
		if e != nil || got != value {
			t.Fatalf("semi boundary %d => %d: %v", value, got, e)
		}
	}
	if got, e := addNonNegativeOffset(math.MinInt64, 1<<63); e != nil || got != 0 {
		t.Fatalf("cross zero %d: %v", got, e)
	}
	if got, e := addNonNegativeOffset(math.MinInt64, math.MaxUint64); e != nil || got != math.MaxInt64 {
		t.Fatalf("maximum offset %d: %v", got, e)
	}
}

func TestCensusBigIntegerValidation(t *testing.T) {
	for _, bounds := range [][2]int64{{0, 0}, {1, 1}, {-1, 1}, {0, 65536}} {
		lo, hi := big.NewInt(bounds[0]), big.NewInt(bounds[1])
		w := NewBitBuffer()
		if e := EncodeIntegerBigBoundsAligned(w, lo, lo, hi, false); e != nil {
			t.Fatal(e)
		}
		got, e := DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(w.CompleteBytes()), lo, hi, false)
		if e != nil || got.Cmp(lo) != 0 {
			t.Fatalf("singleton/boundary %v: %v", got, e)
		}
	}
	for _, tc := range []struct {
		name string
		run  func() error
		want error
	}{
		{"nil", func() error { return EncodeIntegerBigBoundsAligned(NewBitBuffer(), nil, nil, nil, false) }, ErrInvalidValue},
		{"below semi lower", func() error {
			return EncodeIntegerBigBoundsAligned(NewBitBuffer(), big.NewInt(1), big.NewInt(2), nil, false)
		}, ErrConstraintViolation},
		{"above upper", func() error {
			return EncodeIntegerBigBoundsAligned(NewBitBuffer(), big.NewInt(3), nil, big.NewInt(2), false)
		}, ErrConstraintViolation},
		{"private reversed encode", func() error {
			return encodeConstrainedBig(NewBitBuffer(), big.NewInt(1), big.NewInt(2), big.NewInt(0), true)
		}, ErrInvalidValue},
		{"private outside encode", func() error {
			return encodeConstrainedBig(NewBitBuffer(), big.NewInt(3), big.NewInt(0), big.NewInt(2), true)
		}, ErrConstraintViolation},
		{"private reversed decode", func() error {
			_, e := decodeConstrainedBig(NewBitBufferFromBytes(nil), big.NewInt(2), big.NewInt(0), true)
			return e
		}, ErrInvalidValue},
		{"private unused small code", func() error {
			_, e := decodeConstrainedBig(NewBitBufferFromBytes([]byte{0xc0}), big.NewInt(0), big.NewInt(2), true)
			return e
		}, ErrInvalidValue},
		{"private unused large code", func() error {
			_, e := decodeConstrainedBig(NewBitBufferFromBytes([]byte{0x80, 1, 0x86, 0xa1}), big.NewInt(0), big.NewInt(100000), true)
			return e
		}, ErrInvalidValue},
		{"negative write bit count", func() error { return writeBigBits(NewBitBuffer(), big.NewInt(1), -1) }, ErrInvalidValue},
		{"negative read bit count", func() error { _, e := readBigBits(NewBitBufferFromBytes(nil), -1); return e }, ErrInvalidValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.run(); !errors.Is(e, tc.want) {
				t.Fatalf("guard: %v, want %v", e, tc.want)
			}
		})
	}
	for _, value := range []int64{0, 1, 15, 16} {
		w := NewBitBuffer()
		if e := EncodeIntegerBigBoundsAligned(w, big.NewInt(value), big.NewInt(1), big.NewInt(15), true); e != nil {
			t.Fatal(e)
		}
		outside := w.Bytes()[0]&0x80 != 0
		if outside != (value < 1 || value > 15) {
			t.Fatalf("value %d extension bit=%v", value, outside)
		}
	}
	// An upper-only decode still validates the value read as unconstrained.
	w := NewBitBuffer()
	if e := encodeBigTwosComplement(w, big.NewInt(3), true); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeIntegerBigBoundsAligned(NewBitBufferFromBytes(w.Bytes()), nil, big.NewInt(2), false); !errors.Is(e, ErrConstraintViolation) {
		t.Fatal(e)
	}
	// A >int64 value uses a valid arbitrary-width INTEGER but cannot be narrowed.
	w = NewBitBuffer()
	if e := encodeBigTwosComplement(w, new(big.Int).Lsh(big.NewInt(1), 64), true); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeUnconstrainedWholeNumberAligned(NewBitBufferFromBytes(w.Bytes())); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	// Large constrained roots use fragmented octets; check both their declared
	// content length and the unused codes inside a full-width final octet.
	upper := new(big.Int).Lsh(big.NewInt(1), 8*bigFragmentThreshold-1)
	for _, extra := range []int{0, 1} {
		payload := bytes.Repeat([]byte{0xff}, bigFragmentThreshold+extra)
		wire := NewBitBuffer()
		if e := encodeLengthDelimitedOctets(wire, payload, true); e != nil {
			t.Fatal(e)
		}
		_, e := decodeConstrainedBig(NewBitBufferFromBytes(wire.Bytes()), big.NewInt(0), upper, true)
		want := ErrInvalidValue
		if extra != 0 {
			want = ErrConstraintViolation
		}
		if !errors.Is(e, want) {
			t.Fatalf("fragment width +%d: %v", extra, e)
		}
	}
}

func TestCensusStickyBudgetsAndBalance(t *testing.T) {
	b := NewBitBufferFromBytes([]byte{0})
	if e := b.setDecodeSettingsAligned(decodeSettings{Limits: decodeLimits{MaxWork: 1}}); e != nil {
		t.Fatal(e)
	}
	if _, e := b.ReadBits(2); !errors.Is(e, ErrResourceLimit) {
		t.Fatal(e)
	}
	first := b.budget.err
	for _, run := range []func() error{b.EnterDecodeValue, b.EnterOpenType, func() error { return b.ChargeElements(0) }, func() error { return b.checkRecoveryBits(0) }} {
		if e := run(); e != first {
			t.Fatalf("sticky error changed: %v != %v", e, first)
		}
	}
	b = NewBitBufferFromBytes([]byte{0})
	if e := b.ChargeElements(-1); !errors.Is(e, ErrInvalidValue) {
		t.Fatalf("negative charge: %v", e)
	}
	for i := 0; i < 3; i++ {
		if e := b.EnterDecodeValue(); e != nil {
			t.Fatal(e)
		}
		b.LeaveDecodeValue()
		b.LeaveDecodeValue()
		if e := b.EnterOpenType(); e != nil {
			t.Fatal(e)
		}
		b.LeaveOpenType()
		b.LeaveOpenType()
		if b.budget.depth != 0 || b.budget.openDepth != 0 {
			t.Fatalf("unbalanced budget: %+v", b.budget)
		}
	}
	var usage DecodeUsage
	if e := b.setDecodeSettingsAligned(decodeSettings{Usage: &usage, ExtensionRecoveryTolerance: &ToleranceLog{}}); e != nil {
		t.Fatal(e)
	}
	if b.trace.work.limit != uint64(len(b.data)*8)*recoveryWorkInputMultiple {
		t.Fatalf("input work ceiling=%d", b.trace.work.limit)
	}
	b.trace.work.active = true
	for i := 0; i < 4; i++ {
		if e := b.examineRecoveryBits(8); e != nil {
			t.Fatal(e)
		}
	}
	e := b.checkRecoveryBits(1)
	if !errors.Is(e, ErrResourceLimit) {
		t.Fatal(e)
	}
	if got := b.checkRecoveryBits(0); got != e {
		t.Fatalf("recovery failure resumed: %v", got)
	}
	if usage.Work != 32 {
		t.Fatalf("reported work=%d", usage.Work)
	}
}

func TestCensusFragmentPreflight(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func() error
		text string
	}{
		{"negative determinant", func() error { _, _, e := encodeLengthFragmentDeterminant(NewBitBuffer(), -1, true); return e }, "negative"},
		{"octet storage", func() error {
			_, e := DecodeOctetStringAligned(NewBitBufferFromBytes([]byte{2, 0}), 0, 0, false)
			return e
		}, "fragment requires 2 octets with 8 bits remaining"},
		{"bit storage", func() error {
			_, _, e := DecodeBitStringAligned(NewBitBufferFromBytes([]byte{9, 0}), 0, 0, false)
			return e
		}, "BIT STRING fragment requires 9 bits with 8 remaining"},
		{"bit encode storage", func() error { return encodeLengthDelimitedBits(NewBitBuffer(), nil, 1, true) }, "requires 1 octets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.run()
			if e == nil || !strings.Contains(e.Error(), tc.text) {
				t.Fatalf("preflight: %v, want %q", e, tc.text)
			}
		})
	}
	if e := encodeLengthDelimitedBits(NewBitBuffer(), nil, 0, true); e != nil {
		t.Fatal(e)
	}
	if e := encodeLengthDelimitedOctets(NewBitBuffer(), nil, true); e != nil {
		t.Fatal(e)
	}
	// Setting the extension bit cannot evade a root collection size.
	w := NewBitBuffer()
	if e := w.WriteBit(1); e != nil {
		t.Fatal(e)
	}
	if e := EncodeLengthFragments(w, 1, true, func(int64, int64) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodeCollection(NewBitBufferFromBytes(w.Bytes()), SizeConstraint{Lower: 1, Upper: 2, HasLower: true, HasUpper: true, Extensible: true}, true, func(int64, int64) error { return nil }); !errors.Is(e, ErrInvalidValue) {
		t.Fatalf("root collection in extension form: %v", e)
	}
}

func TestCensusPaddingAndScopeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		bb      *BitBuffer
		want    error
		message string
	}{
		{&BitBuffer{invalidLength: true}, ErrInvalidValue, "input bit length exceeds int"},
		{NewBitBufferFromBytes(nil), ErrTruncated, "complete encoding is empty"},
		{&BitBuffer{data: []byte{0}, bitLen: 7}, ErrTruncated, "zero-bit complete encoding has 7 bits"},
	} {
		_, e := captureTrailingPadding(tc.bb, "probe")
		if !errors.Is(e, tc.want) || !strings.Contains(e.Error(), tc.message) {
			t.Fatalf("padding: %v", e)
		}
	}
	if got := (FinalPadding{}).Padding(); got != (CompletePadding{}) {
		t.Fatal(got)
	}
	strict := NewBitBufferFromBytes([]byte{0})
	if strict.EnterComponent("Value") != 0 {
		t.Fatal("strict mark")
	}
	strict.LeaveComponent(0)
	strict.commitRecords("Value")
	parent := NewBitBufferFromBytes([]byte{0})
	if e := parent.setDecodeSettingsAligned(decodeSettings{ExtensionRecoveryTolerance: &ToleranceLog{}, Limits: decodeLimits{MaxWork: 1}}); e != nil {
		t.Fatal(e)
	}
	child := NewNestedDecodeBuffer([]byte{0}, parent)
	if e := child.EnterOpenType(); e != nil {
		t.Fatal(e)
	}
	checkpoint := child.CheckpointKnownAddition()
	if _, e := child.ReadBits(2); !errors.Is(e, ErrResourceLimit) {
		t.Fatal(e)
	}
	a := ExtensionAdditions{present: []bool{true}}
	if ok, _, e := a.CompleteKnownAddition(child, 0, []byte{0}, checkpoint, ErrTruncated); ok || !errors.Is(e, ErrResourceLimit) || !a.present[0] {
		t.Fatalf("resource error recovered: %v %v", ok, e)
	}
	if child.budget.openDepth != 0 {
		t.Fatal("candidate scope leaked")
	}
	parent = NewBitBufferFromBytes([]byte{0})
	child = NewNestedDecodeBuffer(nil, parent)
	if e := child.EnterOpenType(); e != nil {
		t.Fatal(e)
	}
	checkpoint = child.CheckpointKnownAddition()
	if _, _, e := a.CompleteKnownAddition(child, 0, nil, checkpoint, nil); e == nil || !strings.Contains(e.Error(), "ExtData_[0]") {
		t.Fatalf("padding error location: %v", e)
	}
}

func TestCensusRecoveryChargeWindow(t *testing.T) {
	b := NewBitBufferFromBytes([]byte{0})
	if got := b.recoveryCharge(1); got != 0 {
		t.Fatal(got)
	}
	if e := b.setDecodeSettingsAligned(decodeSettings{ExtensionRecoveryTolerance: &ToleranceLog{}}); e != nil {
		t.Fatal(e)
	}
	work := b.trace.work
	work.recordRollback(nil, 1)
	work.recordRollback(b.data, 0)
	if len(work.rolledBack) != 0 {
		t.Fatal("empty rollback recorded")
	}
	work.recordRollback(b.data, 3)
	work.recordRollback(b.data, 1)
	if work.rolledBack[&b.data[0]] != 3 {
		t.Fatal("rollback refunded consumed prefix")
	}
	b.bitPos = 2
	if got := b.recoveryCharge(4); got != 1 {
		t.Fatalf("prefix charge=%d", got)
	}
	b.bitPos = 3
	if got := b.recoveryCharge(4); got != 0 {
		t.Fatalf("unread suffix charge=%d", got)
	}
	b.bitPos = -1
	if got := b.recoveryCharge(1); got != 0 {
		t.Fatalf("negative position charged=%d", got)
	}
	work.active = true
	if got := b.recoveryCharge(4); got != 4 {
		t.Fatalf("provenance charge=%d", got)
	}
}

func TestCensusReplayRecordState(t *testing.T) {
	a := ExtensionAdditions{recovered: true, present: []bool{false, false}}
	if !a.Emptied() {
		t.Fatal("fully recovered additions remained")
	}
	a.present[1] = true
	if a.Emptied() {
		t.Fatal("live addition was omitted")
	}
	padding := finalPaddingOf(CompletePadding{bits: 1, count: 3})
	if got := a.Record(padding); got != padding {
		t.Fatal("no cut changed final padding")
	}
	a.cut = &truncatedExtension{input: []byte{0}, bits: 8, expected: []byte{0}, expectedBits: 8}
	final := a.Record(padding)
	if final.Padding() != padding.Padding() || !final.Truncated() {
		t.Fatal("cut record lost padding")
	}
	bb := NewBitBufferFromBytes([]byte{0})
	if a.Received(bb, 0) {
		t.Fatal("existing cut became received")
	}
	// Received must stay false once the first cut has already been retained.
	if a.Received(bb, 1) {
		t.Fatal("addition after cut became received")
	}
}

func TestCensusScalarAcceptedBoundaries(t *testing.T) {
	for _, value := range []int64{256, 65536, 100000} {
		w := NewBitBuffer()
		if err := EncodeConstrainedWholeNumberAligned(w, value, 0, 100000); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeConstrainedWholeNumberAligned(NewBitBufferFromBytes(w.CompleteBytes()), 0, 100000)
		if err != nil || got != value {
			t.Fatalf("large constrained %d => %d: %v", value, got, err)
		}
	}
	w := NewBitBuffer()
	if err := EncodeEnumeratedAligned(w, 3, 3, true); err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeEnumeratedAligned(NewBitBufferFromBytes(w.CompleteBytes()), 3, true); err != nil || got != 3 {
		t.Fatalf("first extension enumeration: %d %v", got, err)
	}
	for _, value := range []int64{128, 255} {
		got, err := minimalBigTwosComplement(big.NewInt(value))
		if err != nil || !bytes.Equal(got, []byte{0, byte(value)}) {
			t.Fatalf("positive sign octet: %x %v", got, err)
		}
	}
	b := NewBitBufferFromBytes([]byte{0})
	err := b.setDecodeSettingsAligned(decodeSettings{Limits: decodeLimits{MaxWork: -1}})
	if !errors.Is(err, ErrInvalidValue) || b.budget.err != err {
		t.Fatalf("invalid limit not sticky: %v %+v", err, b.budget)
	}
	if _, got := b.ReadBit(); got != err {
		t.Fatalf("discarded option error resumed decode: %v", got)
	}
	// A new top-level call resets caller-owned sticky state and scopes.
	var budget DecodeBudget
	b = NewDecodeBuffer([]byte{0}, &budget)
	if err := b.setDecodeSettingsAligned(decodeSettings{Limits: decodeLimits{MaxWork: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := b.EnterDecodeValue(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReadBits(2); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("first top-level decode did not exhaust its budget: %v", err)
	}
	b = NewDecodeBuffer([]byte{0}, &budget)
	if _, err := b.ReadBit(); err != nil || budget.depth != 0 {
		t.Fatalf("top-level budget reuse: %+v %v", budget, err)
	}
}

func TestCensusCollectionValidationBeforeCallback(t *testing.T) {
	w := NewBitBuffer()
	size := SizeConstraint{Lower: 2, Upper: 5, HasLower: true, HasUpper: true}
	if err := EncodeCollection(w, 2, size, true, func(int64, int64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n, err := DecodeCollection(NewBitBufferFromBytes(w.CompleteBytes()), size, true, func(_ int64, n int64) error {
		if n != 2 {
			t.Fatalf("lower-bound offset gave %d", n)
		}
		return nil
	}); err != nil || n != 2 {
		t.Fatalf("root collection: %d %v", n, err)
	}
	w = NewBitBuffer()
	if err := EncodeLengthFragments(w, 65537, true, func(int64, int64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	callbacks := 0
	_, err := DecodeCollection(NewBitBufferFromBytes(w.CompleteBytes()), SizeConstraint{Upper: 65536, HasUpper: true}, true, func(int64, int64) error { callbacks++; return nil })
	if !errors.Is(err, ErrConstraintViolation) || callbacks != 1 {
		t.Fatalf("upper preflight callbacks=%d: %v", callbacks, err)
	}
	w = NewBitBuffer()
	if err := EncodeLengthFragments(w, 0, true, func(int64, int64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, err = DecodeCollection(NewBitBufferFromBytes(w.CompleteBytes()), SizeConstraint{Lower: 1, HasLower: true}, true, func(int64, int64) error { return nil })
	if !errors.Is(err, ErrConstraintViolation) {
		t.Fatalf("root lower bound: %v", err)
	}
}

func TestCensusLocalReplayPreservesOuterPrefix(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0xad, 0x80})
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	a := BeginExtensionAdditions(bb)
	if _, err := bb.ReadBits(6); err != nil {
		t.Fatal(err)
	}
	a.recovered = true
	expected, err := a.RecoveryEncoder(bb)
	if err != nil {
		t.Fatal(err)
	}
	if expected.BitPos() != 3 || expected.Bytes()[0] != 0 {
		t.Fatalf("local alignment copied outer prefix: %x", expected.Bytes())
	}
	if err := expected.WriteBits(0x15, 6); err != nil {
		t.Fatal(err)
	}
	observed := finalPaddingOf(CompletePadding{bits: 1, count: 7})
	final, err := a.RecordRecovery(bb, expected, observed)
	if err != nil {
		t.Fatal(err)
	}
	if final.Padding() != observed.Padding() || final.Trailing().BitLength != 0 {
		t.Fatal("local recovery lost observed padding or acquired a suffix")
	}
	if !a.Recovered() || !final.Recovered() || final.Truncated() {
		t.Fatal("bounded recovery provenance lost")
	}
	for _, edited := range []bool{false, true} {
		w := NewBitBuffer()
		if err := w.WriteBits(2, 3); err != nil {
			t.Fatal(err)
		}
		value := uint64(0x15)
		if edited {
			value ^= 1
		}
		if err := w.WriteBits(value, 6); err != nil {
			t.Fatal(err)
		}
		AppendExtensionRecovery(w, final, 3)
		r := NewBitBufferFromBytes(w.Bytes())
		prefix, err := r.ReadBits(3)
		if err != nil || prefix != 2 {
			t.Fatalf("outer prefix changed: %d %v", prefix, err)
		}
		local, err := r.ReadBits(6)
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(0x1b)
		if edited {
			want = value
		}
		if local != want {
			t.Fatalf("edited=%v replay=%x want %x", edited, local, want)
		}
	}
	short := NewBitBuffer()
	if err := short.WriteBits(0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RecordRecovery(bb, short, FinalPadding{}); !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "ends before its alignment context") {
		t.Fatalf("missing alignment context: %v", err)
	}
}

func TestCensusExtensionLengthsAndReceiveFailures(t *testing.T) {
	for _, bitString := range []bool{false, true} {
		w := NewBitBuffer()
		if err := w.WriteBit(1); err != nil {
			t.Fatal(err)
		}
		var err error
		if bitString {
			err = encodeLengthDelimitedBits(w, []byte{0x80}, 1, true)
		} else {
			err = encodeLengthDelimitedOctets(w, []byte{0x80}, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		r := NewBitBufferFromBytes(w.CompleteBytes())
		if bitString {
			_, _, err = DecodeBitStringAlignedExt(r, 1, 2, true, true)
		} else {
			_, err = DecodeOctetStringAlignedExt(r, 1, 2, true, true)
		}
		if !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("extension root length (bits=%v): %v", bitString, err)
		}
	}
	if got := rootSizeMaximum(65536, true); got != 65536 {
		t.Fatalf("root allocation bound %d", got)
	}
	for _, invalid := range []func(*BitBuffer, *ExtensionAdditions){
		func(b *BitBuffer, a *ExtensionAdditions) { b.invalidLength = true },
		func(b *BitBuffer, a *ExtensionAdditions) { b.bitLen = 7 },
		func(b *BitBuffer, a *ExtensionAdditions) { b.bitLen = 16 },
		func(b *BitBuffer, a *ExtensionAdditions) { a.present = nil },
	} {
		b := NewBitBufferFromBytes([]byte{1})
		a := ExtensionAdditions{root: 1, present: []bool{true}, aligned: true}
		invalid(b, &a)
		if !a.receive(b, 0) || a.cut != nil {
			t.Fatal("invalid cut state was committed")
		}
	}
	// A failed provenance copy must leave the addition for ordinary decoding.
	b := NewBitBufferFromBytes([]byte{1})
	a := ExtensionAdditions{present: []bool{true}, aligned: true}
	if !a.receive(b, 0) || a.cut != nil || !a.present[0] {
		t.Fatal("failed cut record committed")
	}
	b = NewBitBufferFromBytes([]byte{1})
	if err := b.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &ToleranceLog{}, Limits: decodeLimits{MaxWork: 16}}); err != nil {
		t.Fatal(err)
	}
	a = ExtensionAdditions{root: 1, present: []bool{true}, aligned: true}
	if !a.receive(b, 0) || a.cut != nil || !a.present[0] {
		t.Fatal("failed cut tail copy committed")
	}
	if !errors.Is(b.budget.err, ErrResourceLimit) {
		t.Fatalf("copy did not exhaust work: %+v", b.budget)
	}
	a = ExtensionAdditions{present: []bool{true}}
	if _, err := a.cutRecord(NewBitBufferFromBytes([]byte{0}), []byte{0}, 0, 0, true); !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "precedes the bitmap end") {
		t.Fatalf("cut before bitmap: %v", err)
	}
	if _, err := a.cutRecord(NewBitBufferFromBytes([]byte{0}), []byte{0}, 0, 0, false); !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "precedes the extension bit") {
		t.Fatalf("root before extension bit: %v", err)
	}
}

func TestCensusRecoveryProvenanceWorkAndScope(t *testing.T) {
	newReader := func() *BitBuffer {
		b := NewBitBufferFromBytes([]byte{0xad, 0x80})
		if err := b.setDecodeSettingsAligned(decodeSettings{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.ReadBits(9); err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := newReader()
	a := ExtensionAdditions{start: 3, recovered: true}
	expected, err := a.RecoveryEncoder(b)
	if err != nil {
		t.Fatal(err)
	}
	if b.trace.work.active {
		t.Fatal("encoder leaked provenance accounting scope")
	}
	if err := expected.WriteBits(0, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RecordRecovery(b, expected, FinalPadding{}); err != nil {
		t.Fatal(err)
	}
	if b.trace.work.active {
		t.Fatal("record leaked provenance accounting scope")
	}
	b = newReader()
	b.trace.work.limit = 0
	a.cut = &truncatedExtension{}
	if _, err := a.RecoveryEncoder(b); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("cut prefix provenance uncharged: %v", err)
	}
	if b.trace.work.active {
		t.Fatal("failed encoder leaked accounting scope")
	}
	b = newReader()
	b.trace.work.limit = 0
	a.cut = nil
	if _, err := a.RecordRecovery(b, expected, FinalPadding{}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("local provenance uncharged: %v", err)
	}
	if b.trace.work.active {
		t.Fatal("failed record leaked accounting scope")
	}
	parent := newReader()
	child := NewNestedDecodeBuffer([]byte{0}, parent)
	if err := child.EnterOpenType(); err != nil {
		t.Fatal(err)
	}
	checkpoint := child.CheckpointKnownAddition()
	child.RecoveryComponent("Nested")
	if _, err := child.ReadBit(); err != nil {
		t.Fatal(err)
	}
	a = ExtensionAdditions{present: []bool{true}}
	ok, _, err := a.CompleteKnownAddition(child, 0, []byte{0}, checkpoint, nil)
	if !ok || err != nil || len(child.trace.path) != checkpoint.path {
		t.Fatalf("successful candidate leaked path: %v %v %+v", ok, err, child.trace.path)
	}
}

func TestCensusLargeRootMinimumLengths(t *testing.T) {
	for _, bitString := range []bool{false, true} {
		var err error
		if bitString {
			_, _, err = DecodeBitStringAligned(NewBitBufferFromBytes([]byte{0}), 1, 65536, true)
		} else {
			_, err = DecodeOctetStringAligned(NewBitBufferFromBytes([]byte{0}), 1, 65536, true)
		}
		if !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("large root minimum (bits=%v): %v", bitString, err)
		}
	}
}
