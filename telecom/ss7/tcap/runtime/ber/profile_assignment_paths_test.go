// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/profile_assignment_paths_test.go; SHA-256 2e4df651384610aaf0a823369dce355bd0869821fe1e112d32296878c0861452.
package ber

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestTCAPProfileAssignmentPaths(t *testing.T) {
	for _, row := range []struct{ root, module, assignment, wire, path string }{
		{"Begin", "TCAPMessages", "Begin", "308106480401020304", "Begin"},
		{"Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke", "30810602010102012d", "Invoke"},
		{"ABRTApdu", "DialoguePDUs", "ABRT-apdu", "648103800100", "ABRT-apdu"},
		{"AARQApdu", "DialoguePDUs", "AARQ-apdu", "60810ba109060704000001001302", "AARQ-apdu"},
		{"ABRTApdu", "DialoguePDUs", "ABRT-apdu", "640480810100", "abort-source"},
		{"ABRTApdu", "DialoguePDUs", "ABRT-apdu", "64820003800100", "ABRT-apdu"},
		{"AARQApdu", "DialoguePDUs", "AARQ-apdu", "600ca10a06810704000001001302", "application-context-name"},
		{"AssociateSourceDiagnostic", "DialoguePDUs", "Associate-source-diagnostic", "a10402810100", "dialogue-service-user"},
		{"RLRQApdu", "DialoguePDUs", "RLRQ-apdu", "620480810100", "reason"},
		{"RLREApdu", "DialoguePDUs", "RLRE-apdu", "630480810100", "reason"},
		{"DialoguePDU", "DialoguePDUs", "DialoguePDU", "640480810100", "dialogueAbort.abort-source"},
		{"ROS", "Remote-Operations-Generic-ROS-PDUs", "ROS", "a1070281010102012d", "invoke.invokeId.present"},
		{"ReturnError", "Remote-Operations-Generic-ROS-PDUs", "ReturnError", "300702010102810101", "errcode.local"},
		{"ReturnResultResult", "Remote-Operations-Generic-ROS-PDUs", "ReturnResult-result", "3006028101010500", "opcode.local"},
		{"Reject", "Remote-Operations-Generic-ROS-PDUs", "Reject", "300702010180810100", "problem.general"},
		{"Begin", "TCAPMessages", "Begin", "300748810401020304", "otid"},
		{"Invoke", "Remote-Operations-Generic-ROS-PDUs", "Invoke", "30070281010102012d", "invokeId.present"},
		{"TCMessage", "TCAPMessages", "TCMessage", "628106480401020304", "begin"},
		{"TCMessage", "TCAPMessages", "TCMessage", "620748810401020304", "begin.otid"},
		{"TCMessage", "TCAPMessages", "TCMessage", "67074901014a810100", "abort.reason.p-abortCause"},
	} {
		t.Run(row.root+"/"+row.path, func(t *testing.T) {
			data, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			source := row.module + "." + row.assignment
			if row.path != row.assignment {
				source += "." + row.path
			}
			var strict *ValidationError
			err = ValidateBERElement(data, TrackTCAPForm(nil, row.root, row.module, row.assignment)...)
			if !errors.As(err, &strict) {
				t.Fatalf("missing validation error: %v", err)
			}
			if strict.Path != row.path || strict.Source != source || !strings.HasPrefix(strict.Error(), row.path+" value ") {
				t.Fatalf("got %v source %q; want path %q source %q", strict, strict.Source, row.path, source)
			}
			var log ViolationLog
			err = ValidateBERElement(data, TrackTCAPForm([]DecodeOption{WithTolerance(&log)}, row.root, row.module, row.assignment)...)
			records := log.Snapshot()
			if err != nil || len(records) != 1 || records[0].Path != row.path || records[0].Source != source {
				t.Fatalf("tolerant: %v %+v", err, records)
			}
		})
	}
}

func TestTCAPProfileNamesWithoutSourceMetadata(t *testing.T) {
	data, err := hex.DecodeString("640480810100")
	if err != nil {
		t.Fatal(err)
	}
	var failure *ValidationError
	err = ValidateBERElement(data, TrackTCAPForm(nil, "ABRTApdu")...)
	if !errors.As(err, &failure) || failure.Path != "abort-source" || failure.Source != "ABRTApdu.abort-source" {
		t.Fatalf("unqualified caller lost source component: %v", err)
	}
	err = ValidateBERElement(data)
	if err != nil {
		t.Fatalf("generic BER helper acquired TCAP rules: %v", err)
	}
}
