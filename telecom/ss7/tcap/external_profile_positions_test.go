package tcap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"strings"
	"testing"
)

func externalProfileHex(s string) []byte {
	v, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return v
}

// X.690 (02/2021) §8.18.1; X.680 (02/2021) §31.2.7 b).
// Profile-owned EXTERNALs keep the typed decoder's established diagnostics.
func TestExternalProfileOwnedPositions(t *testing.T) {
	rows := []struct{ name, root, wire, want, path, prefix string }{
		{"user-information", "UserInformation", "300d280b0607040000010101018000", "decoding element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"AARQApdu/user-information", "AARQApdu", "601aa109060704000001000503be0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePDU/dialogueRequest", "DialoguePDU", "601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AARQApdu/single", "DialoguePortion", "6b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AARQApdu/single", "Begin", "302e4801016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AARQApdu/single", "TCMessage", "622e4801016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding begin.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueRequest.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AARQApdu/single", "Continue", "30314801014901026b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AARQApdu/single", "TCMessage", "65314801014901026b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding continue.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueRequest.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AARQApdu/single", "End", "302e4901016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AARQApdu/single", "TCMessage", "642e4901016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding end.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueRequest.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AARQApdu/single", "Unidirectional", "30356b292827060700118605010101a01c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AARQApdu/single", "TCMessage", "61356b292827060700118605010101a01c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueRequest.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AARQApdu/single", "Abort", "302e4901016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding reason.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AARQApdu/single", "TCMessage", "672e4901016b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding abort.reason.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueRequest.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AARQApdu/single", "AbortReason", "6b292827060700118605010101a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AARQApdu/octets", "DialoguePortion", "6b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AARQApdu/octets", "Begin", "302e4801016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AARQApdu/octets", "TCMessage", "622e4801016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding begin.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueRequest.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AARQApdu/octets", "Continue", "30314801014901026b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AARQApdu/octets", "TCMessage", "65314801014901026b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding continue.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueRequest.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AARQApdu/octets", "End", "302e4901016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AARQApdu/octets", "TCMessage", "642e4901016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding end.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueRequest.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AARQApdu/octets", "Unidirectional", "30356b292827060700118605010101811c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AARQApdu/octets", "TCMessage", "61356b292827060700118605010101811c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueRequest.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AARQApdu/octets", "Abort", "302e4901016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding reason.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AARQApdu/octets", "TCMessage", "672e4901016b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding abort.reason.dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueRequest.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AARQApdu/octets", "AbortReason", "6b292827060700118605010101811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding dialogueRequest.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"AAREApdu/user-information", "AAREApdu", "6126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePDU/dialogueResponse", "DialoguePDU", "6126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AAREApdu/single", "DialoguePortion", "6b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AAREApdu/single", "Begin", "303a4801016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AAREApdu/single", "TCMessage", "623a4801016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding begin.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueResponse.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AAREApdu/single", "Continue", "303d4801014901026b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AAREApdu/single", "TCMessage", "653d4801014901026b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding continue.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueResponse.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AAREApdu/single", "End", "303a4901016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AAREApdu/single", "TCMessage", "643a4901016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding end.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueResponse.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AAREApdu/single", "Unidirectional", "30416b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AAREApdu/single", "TCMessage", "61416b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueResponse.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AAREApdu/single", "Abort", "303a4901016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding reason.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AAREApdu/single", "TCMessage", "673a4901016b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding abort.reason.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueResponse.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AAREApdu/single", "AbortReason", "6b352833060700118605010101a0286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AAREApdu/octets", "DialoguePortion", "6b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AAREApdu/octets", "Begin", "303a4801016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AAREApdu/octets", "TCMessage", "623a4801016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding begin.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueResponse.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AAREApdu/octets", "Continue", "303d4801014901026b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AAREApdu/octets", "TCMessage", "653d4801014901026b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding continue.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueResponse.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AAREApdu/octets", "End", "303a4901016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AAREApdu/octets", "TCMessage", "643a4901016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding end.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueResponse.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AAREApdu/octets", "Unidirectional", "30416b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AAREApdu/octets", "TCMessage", "61416b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueResponse.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AAREApdu/octets", "Abort", "303a4901016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding reason.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AAREApdu/octets", "TCMessage", "673a4901016b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding abort.reason.dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueResponse.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AAREApdu/octets", "AbortReason", "6b35283306070011860501010181286126a109060704000001000503a203020100a305a103020100be0d280b0607040000010101018000", "decoding dialogueResponse.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"ABRTApdu/user-information", "ABRTApdu", "6412800100be0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePDU/dialogueAbort", "DialoguePDU", "6412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/ABRTApdu/single", "DialoguePortion", "6b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/ABRTApdu/single", "Begin", "30264801016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/ABRTApdu/single", "TCMessage", "62264801016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding begin.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueAbort.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/ABRTApdu/single", "Continue", "30294801014901026b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/ABRTApdu/single", "TCMessage", "65294801014901026b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding continue.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueAbort.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/ABRTApdu/single", "End", "30264901016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/ABRTApdu/single", "TCMessage", "64264901016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding end.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueAbort.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/ABRTApdu/single", "Unidirectional", "302d6b21281f060700118605010101a0146412800100be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/ABRTApdu/single", "TCMessage", "612d6b21281f060700118605010101a0146412800100be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueAbort.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/ABRTApdu/single", "Abort", "30264901016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding reason.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/ABRTApdu/single", "TCMessage", "67264901016b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding abort.reason.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueAbort.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/ABRTApdu/single", "AbortReason", "6b21281f060700118605010101a0146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/ABRTApdu/octets", "DialoguePortion", "6b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/ABRTApdu/octets", "Begin", "30264801016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/ABRTApdu/octets", "TCMessage", "62264801016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding begin.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialogueAbort.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/ABRTApdu/octets", "Continue", "30294801014901026b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/ABRTApdu/octets", "TCMessage", "65294801014901026b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding continue.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialogueAbort.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/ABRTApdu/octets", "End", "30264901016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/ABRTApdu/octets", "TCMessage", "64264901016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding end.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialogueAbort.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/ABRTApdu/octets", "Unidirectional", "302d6b21281f06070011860501010181146412800100be0d280b06070400000101010180006c08a10602010102012d", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/ABRTApdu/octets", "TCMessage", "612d6b21281f06070011860501010181146412800100be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialogueAbort.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/ABRTApdu/octets", "Abort", "30264901016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding reason.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/ABRTApdu/octets", "TCMessage", "67264901016b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding abort.reason.dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.dialogueAbort.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/ABRTApdu/octets", "AbortReason", "6b21281f06070011860501010181146412800100be0d280b0607040000010101018000", "decoding dialogueAbort.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"AUDTApdu/user-information", "AUDTApdu", "601aa109060704000001000503be0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"UniDialoguePDU/unidialoguePDU", "UniDialoguePDU", "601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AUDTApdu/single", "DialoguePortion", "6b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AUDTApdu/single", "Begin", "302e4801016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AUDTApdu/single", "TCMessage", "622e4801016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding begin.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.unidialoguePDU.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AUDTApdu/single", "Continue", "30314801014901026b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AUDTApdu/single", "TCMessage", "65314801014901026b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding continue.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.unidialoguePDU.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AUDTApdu/single", "End", "302e4901016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AUDTApdu/single", "TCMessage", "642e4901016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding end.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.unidialoguePDU.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AUDTApdu/single", "Unidirectional", "30356b292827060700118605010201a01c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AUDTApdu/single", "TCMessage", "61356b292827060700118605010201a01c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.unidialoguePDU.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AUDTApdu/single", "Abort", "302e4901016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding reason.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AUDTApdu/single", "TCMessage", "672e4901016b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding abort.reason.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.unidialoguePDU.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AUDTApdu/single", "AbortReason", "6b292827060700118605010201a01c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/AUDTApdu/octets", "DialoguePortion", "6b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/AUDTApdu/octets", "Begin", "302e4801016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/AUDTApdu/octets", "TCMessage", "622e4801016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding begin.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.unidialoguePDU.user-information.element[0]", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/AUDTApdu/octets", "Continue", "30314801014901026b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/AUDTApdu/octets", "TCMessage", "65314801014901026b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding continue.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.unidialoguePDU.user-information.element[0]", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/AUDTApdu/octets", "End", "302e4901016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/AUDTApdu/octets", "TCMessage", "642e4901016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding end.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.unidialoguePDU.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/AUDTApdu/octets", "Unidirectional", "30356b292827060700118605010201811c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/AUDTApdu/octets", "TCMessage", "61356b292827060700118605010201811c601aa109060704000001000503be0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.unidialoguePDU.user-information.element[0]", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/AUDTApdu/octets", "Abort", "302e4901016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding reason.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/AUDTApdu/octets", "TCMessage", "672e4901016b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding abort.reason.unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.reason.unidialoguePDU.user-information.element[0]", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/AUDTApdu/octets", "AbortReason", "6b292827060700118605010201811c601aa109060704000001000503be0d280b0607040000010101018000", "decoding unidialoguePDU.user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"RLRQApdu/user-information", "RLRQApdu", "620fbe0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"RLREApdu/user-information", "RLREApdu", "630fbe0d280b0607040000010101018000", "decoding user-information.element[0]: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"DialoguePortion/encoding", "DialoguePortion", "6b0d280b0607040000010101018000", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"Begin/dialogue-encoding", "Begin", "30124801016b0d280b0607040000010101018000", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Begin/dialogue-encoding", "TCMessage", "62124801016b0d280b0607040000010101018000", "decoding begin.dialoguePortion: ber: invalid tag encoding: single-ASN1-type must be explicit", "begin.dialoguePortion", "c100f153af679e451caa81f8b85426d23e9cfcde3d04ce47fc98550767764f9d"},
		{"Continue/dialogue-encoding", "Continue", "30154801014901026b0d280b0607040000010101018000", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Continue/dialogue-encoding", "TCMessage", "65154801014901026b0d280b0607040000010101018000", "decoding continue.dialoguePortion: ber: invalid tag encoding: single-ASN1-type must be explicit", "continue.dialoguePortion", "fac59cb544d68375410814dcf470fc0b041d320bb1b660e68f6ba1a2ddbc6d37"},
		{"End/dialogue-encoding", "End", "30124901016b0d280b0607040000010101018000", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/End/dialogue-encoding", "TCMessage", "64124901016b0d280b0607040000010101018000", "decoding end.dialoguePortion: ber: invalid tag encoding: single-ASN1-type must be explicit", "end.dialoguePortion", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"Unidirectional/dialogue-encoding", "Unidirectional", "30196b0d280b06070400000101010180006c08a10602010102012d", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Unidirectional/dialogue-encoding", "TCMessage", "61196b0d280b06070400000101010180006c08a10602010102012d", "decoding unidirectional.dialoguePortion: ber: invalid tag encoding: single-ASN1-type must be explicit", "unidirectional.dialoguePortion", "c0e5aeeec994aaf6094c97b9de887014127bbc259a9860bc30d4d48d232c8dc5"},
		{"Abort/dialogue-encoding", "Abort", "30124901016b0d280b0607040000010101018000", "decoding reason: ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
		{"TCMessage/Abort/dialogue-encoding", "TCMessage", "67124901016b0d280b0607040000010101018000", "decoding abort.dialoguePortion: ber: invalid tag encoding: single-ASN1-type must be explicit", "abort.dialoguePortion", "6d976ec6551ef8b7bc6d1f8c13d75e056015b4a0a811266b2f15c8218b24a481"},
		{"AbortReason/dialogue-encoding", "AbortReason", "6b0d280b0607040000010101018000", "ber: invalid tag encoding: single-ASN1-type must be explicit", "", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			data := externalProfileHex(row.wire)
			for _, profile := range []bool{false, true} {
				for _, tolerant := range []bool{false, true} {
					var opts []ber.DecodeOption
					if tolerant {
						opts = append(opts, ber.WithTolerance(new(ber.ViolationLog)))
					}
					if profile {
						opts = ber.TrackTCAPForm(opts, row.root)
					}
					scan := ber.ValidateBERElement(data, opts...)
					scanWant := "ber: invalid tag encoding: single-ASN1-type must be explicit"
					if strings.Contains(row.name, "/octets") {
						scanWant = "<nil>"
					}
					if profile {
						scanWant = "ber: invalid tag encoding: primitive EXPLICIT wrapper"
					}
					if fmt.Sprint(scan) != scanWant {
						t.Fatalf("profile=%t scan=%v, want %s", profile, scan, scanWant)
					}
					err := externalProfileCodec(row.root).UnmarshalBER(data, opts...)
					var de *DecodeError
					errors.As(err, &de)
					path := ""
					var prefix any
					if de != nil {
						path = de.Path
						prefix = de.Prefix
					}
					raw, jsonErr := json.Marshal(prefix)
					if jsonErr != nil {
						t.Fatal(jsonErr)
					}
					if fmt.Sprint(err) != row.want || path != row.path || fmt.Sprintf("%x", sha256.Sum256(raw)) != row.prefix {
						t.Fatalf("profile=%t tolerant=%t got error=%v Path=%q Prefix=%s, want error=%s Path=%q PrefixSHA256=%s", profile, tolerant, err, path, raw, row.want, row.path, row.prefix)
					}
					for _, sent := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
						if errors.Is(err, sent) != (sent == ber.ErrInvalidTag) {
							t.Fatalf("error=%v errors.Is(%v)", err, sent)
						}
					}
				}
			}
		})
	}
}
func externalProfileCodec(root string) interface {
	UnmarshalBER([]byte, ...ber.DecodeOption) error
} {
	switch root {
	case "AAREApdu":
		return new(AAREApdu)
	case "AARQApdu":
		return new(AARQApdu)
	case "ABRTApdu":
		return new(ABRTApdu)
	case "AUDTApdu":
		return new(AUDTApdu)
	case "Abort":
		return new(Abort)
	case "AbortReason":
		return new(AbortReason)
	case "Begin":
		return new(Begin)
	case "Continue":
		return new(Continue)
	case "DialoguePDU":
		return new(DialoguePDU)
	case "DialoguePortion":
		return new(DialoguePortion)
	case "End":
		return new(End)
	case "RLREApdu":
		return new(RLREApdu)
	case "RLRQApdu":
		return new(RLRQApdu)
	case "TCMessage":
		return new(TCMessage)
	case "UniDialoguePDU":
		return new(UniDialoguePDU)
	case "Unidirectional":
		return new(Unidirectional)
	case "UserInformation":
		return new(UserInformation)
	}
	panic(root)
}

// X.690 (02/2021) §8.18.1 has one encoding choice; a later [0]
// remains a complete element outside the abstract syntax.
func TestExternalTrailingEncodingPosition(t *testing.T) {
	wire := externalProfileHex("62244804000000016b1c281a060700118605010101a00d600ba1090607040000010005038000")
	for _, opts := range [][]ber.DecodeOption{nil, {ber.WithTolerance(new(ber.ViolationLog))}} {
		if err := ber.ValidateBERElement(wire, ber.TrackTCAPForm(opts, "TCMessage")...); err != nil {
			t.Fatal(err)
		}
		var value TCMessage
		err := value.UnmarshalBER(wire, opts...)
		var de *DecodeError
		if !errors.As(err, &de) || de.Path != "begin.dialoguePortion" {
			t.Fatalf("error=%v, want begin.dialoguePortion", err)
		}
		for _, sent := range []error{ber.ErrTruncated, ber.ErrInvalidTag, ber.ErrUnexpectedElement, ber.ErrInvalidLength, ber.ErrIndefiniteLength, ber.ErrExtraData, ber.ErrInvalidValue, ber.ErrUnsupported, ber.ErrResourceLimit} {
			if errors.Is(err, sent) != (sent == ber.ErrUnexpectedElement) {
				t.Fatalf("error=%v errors.Is(%v)", err, sent)
			}
		}
	}
}
