package per

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestContainedDecodingNames(t *testing.T) {
	for mode, want := range map[ContainedDecoding]string{Eager: "Eager", DeferOnError: "DeferOnError", DeferAll: "DeferAll", 9: "ContainedDecoding(9)"} {
		if mode.String() != want {
			t.Errorf("%d: %q", mode, mode.String())
		}
	}
	for kind, want := range map[ContainerKind]string{OctetStringContainer: "OCTET STRING", BitStringContainer: "BIT STRING", 0: "ContainerKind(0)"} {
		if kind.String() != want {
			t.Errorf("%d: %q", kind, kind.String())
		}
	}
}

// Only a decode that tolerates or defers pays for a trace.
func TestStrictEagerDecodeHasNoTrace(t *testing.T) {
	bb := NewBitBufferFromBytes([]byte{0})
	bb.SetDecodeOptions(DecodeOptions{Deferrals: &DeferralLog{}})
	if bb.trace != nil {
		t.Fatal("an Eager decode without tolerance allocated a trace")
	}
	bb.SetDecodeOptions(DecodeOptions{ContainedDecoding: DeferAll, Deferrals: &DeferralLog{}})
	if bb.trace == nil {
		t.Fatal("a deferring decode has no trace for its record paths")
	}
	if site := bb.EnterContained(); site.Decodes() || site.DefersErrors() {
		t.Fatalf("DeferAll site = %+v", site)
	}
	bb.SetDecodeOptions(DecodeOptions{})
	if site := bb.EnterContained(); !site.Decodes() || site.DefersErrors() || site.trace != nil {
		t.Fatalf("Eager site = %+v", site)
	}
}

// A deferral drops what the abandoned decode recorded and left on the path,
// and is published with the decode's full path, also inside its error.
func TestDeferralRollsBackAbandonedDecode(t *testing.T) {
	var tolerances ToleranceLog
	var deferrals DeferralLog
	bb := NewBitBufferFromBytes([]byte{0xa0})
	bb.SetDecodeOptions(DecodeOptions{TrailingBitsTolerance: &tolerances, ContainedDecoding: DeferOnError, Deferrals: &deferrals})
	mark := bb.EnterIndex(3)
	field := bb.EnterComponent("Field")
	site := bb.EnterContained()

	// The contained decode records a tolerance and a nested deferral, then
	// fails inside a component it entered.
	child := NewBitBufferFromBytes([]byte{0x80, 0xff})
	child.InheritDecodeOptions(bb)
	child.EnterComponent("Nested")
	if _, err := child.ReadBits(1); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureContainedFinalBits(child); err != nil {
		t.Fatal(err)
	}
	child.EnterContained().DeferBits([]byte{0x80}, 1, errors.New("nested"))
	if len(bb.trace.pending) != 1 || len(bb.trace.deferred) != 1 {
		t.Fatalf("nested records = %+v, %+v", bb.trace.pending, bb.trace.deferred)
	}
	child.EnterComponent("Failing")

	cause := errors.New("decoding contained field: boom")
	padding := site.DeferOctets([]byte{0x80, 0xff}, cause)
	bb.LeaveComponent(field)
	bb.LeaveComponent(mark)
	if _, err := bb.ReadBits(3); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureFinalBits(bb, "Root"); err != nil {
		t.Fatal(err)
	}
	if records := tolerances.Snapshot(); len(records) != 0 {
		t.Fatalf("abandoned tolerance published: %+v", records)
	}
	records := deferrals.Snapshot()
	if len(records) != 1 {
		t.Fatalf("deferrals = %+v", records)
	}
	record := records[0]
	if record.Path != "Root[3].Field" || record.Kind != OctetStringContainer || record.BitLength != 16 || !errors.Is(record.Err, cause) {
		t.Fatalf("record = %+v", record)
	}
	if record.Err.Error() != "decoding Root[3].Field: decoding contained field: boom" {
		t.Fatalf("record error %q", record.Err)
	}
	d := padding.Deferred()
	if d == nil || d.Err() != record.Err || d.Kind() != OctetStringContainer || d.BitLength() != 16 || !bytes.Equal(d.Bytes(), []byte{0x80, 0xff}) {
		t.Fatalf("deferred = %+v", d)
	}
	if padding.Trailing().BitLength != 0 || !padding.IsZero() {
		t.Fatal("deferred state reads as retained bits")
	}
	if (FinalPadding{}).Deferred() != nil || finalPaddingOf(CompletePadding{bits: 1, count: 1}).Deferred() != nil {
		t.Fatal("ordinary padding reads as deferred")
	}
}

// DeferAll records no error, and a decode without a trace still keeps the
// raw state.
func TestDeferWithoutError(t *testing.T) {
	var deferrals DeferralLog
	bb := NewBitBufferFromBytes([]byte{0})
	bb.SetDecodeOptions(DecodeOptions{ContainedDecoding: DeferAll, Deferrals: &deferrals})
	bb.EnterComponent("Bits")
	d := bb.EnterContained().DeferBits([]byte{0xe0}, 3, nil).Deferred()
	if d.Err() != nil || d.BitLength() != 3 || d.Kind() != BitStringContainer {
		t.Fatalf("deferred = %+v", d)
	}
	if _, err := CaptureFinalBits(bb, "Root"); err != nil {
		t.Fatal(err)
	}
	if records := deferrals.Snapshot(); len(records) != 1 || records[0].Err != nil || records[0].Path != "Root.Bits" {
		t.Fatalf("records = %+v", records)
	}
	untraced := (ContainedSite{mode: DeferOnError}).DeferOctets(nil, errors.New("x")).Deferred()
	if untraced.Err() == nil || untraced.BitLength() != 0 {
		t.Fatalf("untraced = %+v", untraced)
	}
}

func TestContainedDecodingRequiresLog(t *testing.T) {
	for _, options := range []DecodeOptions{
		{ContainedDecoding: DeferOnError},
		{ContainedDecoding: DeferAll, TrailingBitsTolerance: &ToleranceLog{}},
		{ContainedDecoding: 7, Deferrals: &DeferralLog{}},
	} {
		bb := NewBitBufferFromBytes([]byte{0})
		bb.SetDecodeOptions(options)
		if _, err := CaptureFinalBits(bb, "Root"); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%+v: %v", options, err)
		}
		bits, _ := NewBitBufferFromBits([]byte{0}, 1)
		bits.SetDecodeOptions(options)
		if _, err := CaptureDeferredBits(bits, "Root"); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("deferred bits %+v: %v", options, err)
		}
	}
}

type testShell struct {
	Value       int
	List        []byte
	PERPadding_ FinalPadding
}

func deferredPadding(kind ContainerKind, raw []byte, bitLength int) FinalPadding {
	if kind == OctetStringContainer {
		return ContainedSite{}.DeferOctets(raw, nil)
	}
	return ContainedSite{}.DeferBits(raw, bitLength, nil)
}

func TestDeferredEncoding(t *testing.T) {
	octets := deferredPadding(OctetStringContainer, []byte{0x12, 0x34}, 0)
	bits := deferredPadding(BitStringContainer, []byte{0xa8}, 5)

	shell := &testShell{PERPadding_: octets}
	out, err := MarshalDeferred(shell, shell.PERPadding_)
	if err != nil || !bytes.Equal(out, []byte{0x12, 0x34}) {
		t.Fatalf("MarshalDeferred = %x, %v", out, err)
	}
	out[0] = 0
	if again, _ := MarshalDeferred(shell, shell.PERPadding_); again[0] != 0x12 {
		t.Fatal("MarshalDeferred aliases the raw contents")
	}
	bb := NewBitBuffer()
	if err := bb.WriteBit(1); err != nil {
		t.Fatal(err)
	}
	bitShell := &testShell{PERPadding_: bits}
	if err := AppendDeferred(bb, bitShell, bitShell.PERPadding_); err != nil || bb.BitsWritten() != 6 || bb.Bytes()[0] != 0xd4 {
		t.Fatalf("AppendDeferred = %x/%d, %v", bb.Bytes(), bb.BitsWritten(), err)
	}

	for name, edit := range map[string]func(*testShell){"value": func(s *testShell) { s.Value = 1 }, "slice": func(s *testShell) { s.List = []byte{} }} {
		edited := &testShell{PERPadding_: octets}
		edit(edited)
		if _, err := MarshalDeferred(edited, edited.PERPadding_); !errors.Is(err, ErrEditedDeferred) {
			t.Errorf("%s edit: %v", name, err)
		}
		edited.PERPadding_ = bits
		if err := AppendDeferred(NewBitBuffer(), edited, edited.PERPadding_); !errors.Is(err, ErrEditedDeferred) {
			t.Errorf("%s edit, bits: %v", name, err)
		}
	}
	// The check reads state: a zero value assigned to a field is no edit.
	zeroed := &testShell{Value: 0, List: nil, PERPadding_: octets}
	if out, err := MarshalDeferred(zeroed, zeroed.PERPadding_); err != nil || !bytes.Equal(out, []byte{0x12, 0x34}) {
		t.Errorf("zero assignment: %x, %v", out, err)
	}
	if _, err := MarshalDeferred(bitShell, bitShell.PERPadding_); !errors.Is(err, ErrMisplacedDeferred) {
		t.Errorf("BIT contents as a complete encoding: %v", err)
	}
	if err := AppendDeferred(NewBitBuffer(), shell, shell.PERPadding_); !errors.Is(err, ErrMisplacedDeferred) {
		t.Errorf("OCTET contents in a BIT STRING: %v", err)
	}
	if _, err := MarshalDeferred(&testShell{}, FinalPadding{}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("no deferred state: %v", err)
	}
	if _, err := MarshalDeferred(*shell, shell.PERPadding_); !errors.Is(err, ErrEditedDeferred) {
		t.Errorf("shell by value: %v", err)
	}
	if _, err := MarshalDeferred((*testShell)(nil), octets); !errors.Is(err, ErrEditedDeferred) {
		t.Errorf("nil shell: %v", err)
	}
}

// A deferred BIT STRING value is decoded later from a bounded buffer, with
// its own options and records.
func TestDeferredBitBuffer(t *testing.T) {
	d := deferredPadding(BitStringContainer, []byte{0xa8}, 5).Deferred()
	var tolerances ToleranceLog
	bb, err := d.BitBuffer(DecodeOptions{TrailingBitsTolerance: &tolerances})
	if err != nil || bb.BitsRemaining() != 5 {
		t.Fatalf("BitBuffer = %v, %v", bb, err)
	}
	if v, err := bb.ReadBits(2); err != nil || v != 2 {
		t.Fatalf("read %d, %v", v, err)
	}
	kept, err := CaptureDeferredBits(bb, "Later")
	if err != nil || kept.Trailing().BitLength != 3 {
		t.Fatalf("CaptureDeferredBits = %+v, %v", kept, err)
	}
	if records := tolerances.Snapshot(); len(records) != 1 || records[0].Path != "Later" || records[0].Kind != ToleratedContainedBits {
		t.Fatalf("records = %+v", records)
	}
	strict, _ := d.BitBuffer(DecodeOptions{})
	if _, err := strict.ReadBits(2); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureDeferredBits(strict, "Later"); !errors.Is(err, ErrExtraData) {
		t.Fatalf("strict later decode: %v", err)
	}
	octets := deferredPadding(OctetStringContainer, []byte{1}, 0).Deferred()
	if _, err := octets.BitBuffer(DecodeOptions{}); err == nil || !strings.Contains(err.Error(), "UnmarshalUPERWithOptions") {
		t.Fatalf("OCTET STRING bit buffer: %v", err)
	}
}

func TestDeferralLogSnapshot(t *testing.T) {
	var log DeferralLog
	log.append([]Deferral{{Path: "A", BitLength: 1}})
	snapshot := log.Snapshot()
	snapshot[0].Path = "B"
	if log.Snapshot()[0].Path != "A" {
		t.Fatal("snapshot aliases the log")
	}
	log.Reset()
	if len(log.Snapshot()) != 0 {
		t.Fatal("reset kept records")
	}
}
