package validation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	"github.com/gomaja/go-asn1/telecom/lte/rrc/runtime/uper"
)

// RRCConnectionSetupComplete inputs of go-asn1 #224 and #207, with empty NAS
// content, that end inside or exactly at the start of the bitmap of the first,
// fourth and eighth nested nonCriticalExtension. The parent's OPTIONAL bitmap
// proves the child present (X.691 (02/2021) §19.2); inferring the absent child
// bitmap is an explicit receiver policy, beyond §§19.3–19.4 and §11.1.3.1.
func TestLTERRCInlineBitmapRecoveryAtBitmapStart(t *testing.T) {
	const root = "ULDCCHMessage.Message.C1.RrcConnectionSetupComplete.CriticalExtensions.C1.RrcConnectionSetupCompleteR8"
	for _, tc := range []struct {
		wire                   string
		depth, received, width int
	}{
		{"221000", 1, 1, 2}, {"22100085", 4, 0, 4}, {"221000859015", 8, 0, 9},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			data, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"strict", "truncated", "recovery", "both"} {
				var log uper.ToleranceLog
				opts := uper.DecodeOptions{}
				if mode == "truncated" || mode == "both" {
					opts.TruncatedExtensionTolerance = &log
				}
				if mode == "recovery" || mode == "both" {
					opts.ExtensionRecoveryTolerance = &log
				}
				var v rrc.ULDCCHMessage
				if err := v.UnmarshalUPERWithOptions(data, opts); !errors.Is(err, uper.ErrTruncated) || len(log.Snapshot()) != 0 {
					t.Fatalf("mode=%s err=%v records=%+v", mode, err, log.Snapshot())
				}
			}
			for _, mode := range []string{"inline", "inline and truncated", "inline and recovery", "all"} {
				t.Run(mode, func(t *testing.T) {
					var log uper.ToleranceLog
					opts := uper.DecodeOptions{InlineBitmapRecoveryTolerance: &log}
					if mode == "inline and truncated" || mode == "all" {
						opts.TruncatedExtensionTolerance = &log
					}
					if mode == "inline and recovery" || mode == "all" {
						opts.ExtensionRecoveryTolerance = &log
					}
					var v rrc.ULDCCHMessage
					if err := v.UnmarshalUPERWithOptions(data, opts); err != nil {
						t.Fatal(err)
					}
					records := log.Snapshot()
					wantPath := root + strings.Repeat(".NonCriticalExtension", tc.depth)
					if len(records) != 1 {
						t.Fatalf("records=%+v", records)
					}
					r := records[0]
					if r.Kind != uper.ToleratedIncompleteInlineBitmap || r.Path != wantPath || r.Offset != len(data)*8 || r.Bits.BitLength != tc.received || len(r.Bits.Bytes) != (tc.received+7)/8 || r.Missing != tc.width-tc.received {
						t.Fatalf("record=%+v want path=%s received=%d missing=%d", r, wantPath, tc.received, tc.width-tc.received)
					}
					if !bytes.Equal(r.Bits.Bytes, make([]byte, (tc.received+7)/8)) {
						t.Fatal("received bitmap is nonzero")
					}
					child := reflect.ValueOf(v)
					for _, part := range strings.Split(strings.TrimPrefix(wantPath, "ULDCCHMessage."), ".") {
						if child.Kind() == reflect.Pointer {
							child = child.Elem()
						}
						child = child.FieldByName(part)
						if !child.IsValid() || child.Kind() == reflect.Pointer && child.IsNil() {
							t.Fatalf("missing child %s", part)
						}
					}
					if !child.Elem().FieldByName("PERPadding_").Interface().(uper.FinalPadding).InferredInlineBitmap() {
						t.Fatal("missing inference marker")
					}
					replay, err := v.MarshalUPER()
					if err != nil || !bytes.Equal(replay, data) {
						t.Fatalf("unchanged replay differs: %v", err)
					}
					setup := v.Message.C1.RrcConnectionSetupComplete
					setup.RrcTransactionIdentifier = (setup.RrcTransactionIdentifier + 1) % 4
					complete, err := v.MarshalUPER()
					if err != nil || len(complete) <= len(data) {
						t.Fatalf("edit did not complete bitmap: length=%d err=%v", len(complete), err)
					}
					var strict rrc.ULDCCHMessage
					if err := strict.UnmarshalUPER(complete); err != nil {
						t.Fatalf("edited encoding rejected: %v", err)
					}
					gotTree, err := json.Marshal(strict)
					if err != nil {
						t.Fatal(err)
					}
					wantTree, err := json.Marshal(v)
					if err != nil || !bytes.Equal(gotTree, wantTree) {
						t.Fatal("edited abstract value differs")
					}
				})
			}
			for _, enabled := range []bool{false, true} {
				allocs := testing.AllocsPerRun(100, func() {
					var v rrc.ULDCCHMessage
					var log uper.ToleranceLog
					opts := uper.DecodeOptions{}
					if enabled {
						opts.InlineBitmapRecoveryTolerance = &log
					}
					_ = v.UnmarshalUPERWithOptions(data, opts)
				})
				t.Logf("inline=%t decode allocations=%.0f", enabled, allocs)
			}
		})
	}
}
