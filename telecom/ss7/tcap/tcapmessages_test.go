package tcap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", s, err)
	}
	return b
}

func testDialoguePortion() DialoguePortion {
	return DialoguePortion{Bytes: testDialoguePortionBytes()}
}

func testDialoguePortionBytes() []byte {
	return []byte{
		0x28, 0x0d,
		0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01,
		0x80, 0x02, 0x60, 0x00,
	}
}

func TestBeginDialoguePortionUsesExplicitExternal(t *testing.T) {
	dialogue := testDialoguePortion()
	begin := Begin{
		Otid:            OrigTransactionID{0x01},
		DialoguePortion: &dialogue,
	}

	got, err := begin.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER: %v", err)
	}
	want := []byte{
		0x30, 0x14,
		0x48, 0x01, 0x01,
		0x6b, 0x0f,
		0x28, 0x0d,
		0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01,
		0x80, 0x02, 0x60, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded bytes: got % x, want % x", got, want)
	}

	var decoded Begin
	if err := decoded.UnmarshalBER(want); err != nil {
		t.Fatalf("UnmarshalBER: %v", err)
	}
	if decoded.DialoguePortion == nil {
		t.Fatalf("decoded dialoguePortion is nil")
	}
	if !bytes.Equal(decoded.DialoguePortion.Bytes, dialogue.Bytes) {
		t.Fatalf("decoded dialoguePortion: got % x, want % x", decoded.DialoguePortion.Bytes, dialogue.Bytes)
	}
}

func TestReasonUsesApplicationTags(t *testing.T) {
	pAbortCause := PAbortCauseBadlyFormattedTransactionPortion
	pReason := NewAbortReasonPAbortCause(pAbortCause)
	got, err := pReason.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER p-abortCause: %v", err)
	}
	wantPAbort := []byte{0x4a, 0x01, 0x02}
	if !bytes.Equal(got, wantPAbort) {
		t.Fatalf("p-abortCause bytes: got % x, want % x", got, wantPAbort)
	}

	var decodedP AbortReason
	if err := decodedP.UnmarshalBER(wantPAbort); err != nil {
		t.Fatalf("UnmarshalBER p-abortCause: %v", err)
	}
	if decodedP.PAbortCause == nil || *decodedP.PAbortCause != pAbortCause {
		t.Fatalf("decoded p-abortCause: got %+v, want %d", decodedP.PAbortCause, pAbortCause)
	}

	dialogue := testDialoguePortion()
	uReason := NewAbortReasonUAbortCause(dialogue)
	got, err = uReason.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER u-abortCause: %v", err)
	}
	wantUAbort := []byte{
		0x6b, 0x0f,
		0x28, 0x0d,
		0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01,
		0x80, 0x02, 0x60, 0x00,
	}
	if !bytes.Equal(got, wantUAbort) {
		t.Fatalf("u-abortCause bytes: got % x, want % x", got, wantUAbort)
	}

	var decodedU AbortReason
	if err := decodedU.UnmarshalBER(wantUAbort); err != nil {
		t.Fatalf("UnmarshalBER u-abortCause: %v", err)
	}
	if decodedU.UAbortCause == nil || !bytes.Equal(decodedU.UAbortCause.Bytes, dialogue.Bytes) {
		t.Fatalf("decoded u-abortCause: got %+v, want %+v", decodedU.UAbortCause, dialogue)
	}
}

func TestReasonUAbortCauseNilReturnsError(t *testing.T) {
	reason := AbortReason{Choice: AbortReasonChoiceUAbortCause}

	_, err := reason.MarshalBER()
	if err == nil {
		t.Fatalf("MarshalBER returned nil error")
	}
	if !strings.Contains(err.Error(), "choice AbortReason: u-abortCause is nil") {
		t.Fatalf("MarshalBER error: got %q", err)
	}
}

func TestAUDTApduUserInformationRequiresSequence(t *testing.T) {
	for _, input := range [][]byte{
		{0x04, 0x00},
		{0x31, 0x00},
	} {
		if got, err := UnmarshalBERAUDTApduUserInformation(input); err == nil {
			t.Fatalf("UnmarshalBERAUDTApduUserInformation(% x) = %+v, nil error", input, got)
		}
	}

	got, err := UnmarshalBERAUDTApduUserInformation([]byte{0x30, 0x02, 0x04, 0x00})
	if err != nil {
		t.Fatalf("UnmarshalBERAUDTApduUserInformation valid sequence: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Bytes, []byte{0x04, 0x00}) {
		t.Fatalf("decoded user-information: got %+v", got)
	}
}

func TestComponentPortionUsesApplicationTag(t *testing.T) {
	got, err := MarshalBERComponentPortion(nil)
	if err != nil {
		t.Fatalf("MarshalBERComponentPortion: %v", err)
	}
	want := []byte{0x6c, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBERComponentPortion = % x, want % x", got, want)
	}

	if _, err := UnmarshalBERComponentPortion(want); err != nil {
		t.Fatalf("UnmarshalBERComponentPortion application tag: %v", err)
	}
	if decoded, err := UnmarshalBERComponentPortion([]byte{0x30, 0x00}); err == nil {
		t.Fatalf("UnmarshalBERComponentPortion universal sequence = %+v, nil error", decoded)
	}
}

func TestComponentPortionDecodesReturnResultLastFixture(t *testing.T) {
	input := mustDecodeHex(t, "6c0fa20d02017f300802012d0403deadbe")

	components, err := UnmarshalBERComponentPortion(input)
	if err != nil {
		t.Fatalf("UnmarshalBERComponentPortion: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("ComponentPortion length = %d, want 1", len(components))
	}

	got, err := MarshalBERComponentPortion(components)
	if err != nil {
		t.Fatalf("MarshalBERComponentPortion: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("ComponentPortion round-trip = % x, want % x", got, input)
	}
}

func TestEndWithReturnResultLastFixtureRoundTrips(t *testing.T) {
	input := mustDecodeHex(t, "64144901016c0fa20d02017f300802012d0403deadbe")

	var msg TCMessage
	if err := msg.UnmarshalBER(input); err != nil {
		t.Fatalf("TCMessage.UnmarshalBER: %v", err)
	}
	if msg.Choice != TCMessageChoiceEnd || msg.End == nil {
		t.Fatalf("TCMessage choice = %d, End = %+v", msg.Choice, msg.End)
	}
	if len(msg.End.Components) != 1 {
		t.Fatalf("End.Components length = %d, want 1", len(msg.End.Components))
	}

	got, err := msg.MarshalBER()
	if err != nil {
		t.Fatalf("TCMessage.MarshalBER: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("TCMessage round-trip = % x, want % x", got, input)
	}
}

func TestBeginWithIndefiniteComponentPortionRoundTrips(t *testing.T) {
	input := mustDecodeHex(t, "620f4801016c80a10602010002012d0000")

	var msg TCMessage
	if err := msg.UnmarshalBER(input); err != nil {
		t.Fatalf("TCMessage.UnmarshalBER: %v", err)
	}
	if msg.Choice != TCMessageChoiceBegin || msg.Begin == nil {
		t.Fatalf("TCMessage choice = %d, Begin = %+v", msg.Choice, msg.Begin)
	}
	if !msg.Begin.ComponentsIndef_ {
		t.Fatalf("Begin.ComponentsIndef_ = false, want true")
	}

	got, err := msg.MarshalBER()
	if err != nil {
		t.Fatalf("TCMessage.MarshalBER: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("TCMessage round-trip = % x, want % x", got, input)
	}
}
