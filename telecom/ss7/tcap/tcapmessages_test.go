package tcap

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func testDialoguePortion() DialoguePortion {
	return DialoguePortion{
		Oid:    DialogueAsId(),
		Dialog: []byte{0x60, 0x00},
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
	if !bytes.Equal(decoded.DialoguePortion.Dialog, dialogue.Dialog) {
		t.Fatalf("decoded dialog: got % x, want % x", decoded.DialoguePortion.Dialog, dialogue.Dialog)
	}
	if !reflect.DeepEqual(decoded.DialoguePortion.Oid, dialogue.Oid) {
		t.Fatalf("decoded oid: got %v, want %v", decoded.DialoguePortion.Oid, dialogue.Oid)
	}
}

func TestReasonUsesApplicationTags(t *testing.T) {
	pAbortCause := PAbortCauseBadlyFormattedTransactionPortion
	pReason := NewReasonPAbortCause(pAbortCause)
	got, err := pReason.MarshalBER()
	if err != nil {
		t.Fatalf("MarshalBER p-abortCause: %v", err)
	}
	wantPAbort := []byte{0x4a, 0x01, 0x02}
	if !bytes.Equal(got, wantPAbort) {
		t.Fatalf("p-abortCause bytes: got % x, want % x", got, wantPAbort)
	}

	var decodedP Reason
	if err := decodedP.UnmarshalBER(wantPAbort); err != nil {
		t.Fatalf("UnmarshalBER p-abortCause: %v", err)
	}
	if decodedP.PAbortCause == nil || *decodedP.PAbortCause != pAbortCause {
		t.Fatalf("decoded p-abortCause: got %+v, want %d", decodedP.PAbortCause, pAbortCause)
	}

	dialogue := testDialoguePortion()
	uReason := NewReasonUAbortCause(dialogue)
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

	var decodedU Reason
	if err := decodedU.UnmarshalBER(wantUAbort); err != nil {
		t.Fatalf("UnmarshalBER u-abortCause: %v", err)
	}
	if decodedU.UAbortCause == nil || !bytes.Equal(decodedU.UAbortCause.Dialog, dialogue.Dialog) {
		t.Fatalf("decoded u-abortCause: got %+v, want %+v", decodedU.UAbortCause, dialogue)
	}
}

func TestReasonUAbortCauseNilReturnsError(t *testing.T) {
	reason := Reason{Choice: ReasonChoiceUAbortCause}

	_, err := reason.MarshalBER()
	if err == nil {
		t.Fatalf("MarshalBER returned nil error")
	}
	if !strings.Contains(err.Error(), "choice Reason: u-abortCause is nil") {
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
