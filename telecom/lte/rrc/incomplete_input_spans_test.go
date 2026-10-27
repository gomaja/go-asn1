package rrc_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	"github.com/gomaja/go-asn1/telecom/lte/rrc/runtime/uper"
)

func TestIncompleteExtensionPublishedInputSpans(t *testing.T) {
	for _, tc := range []struct {
		wire                           string
		local, input, length, consumed int
	}{
		{"5c155060990021040040202468ac00050c", 118, 118, 1, 8},
		{"5c15506099005b0803007101820283008341416181a020020101234560090c80", 75, 129, 6, 10},
	} {
		for _, positions := range []string{"disabled", "enabled", "padding"} {
			t.Run(fmt.Sprint(tc.input)+"/"+positions, func(t *testing.T) {
				data, err := hex.DecodeString(tc.wire)
				if err != nil {
					t.Fatal(err)
				}
				var recovered, padding uper.ToleranceLog
				bb := uper.NewBitBufferFromBytes(data)
				options := uper.DecodeOptions{ExtensionRecoveryTolerance: &recovered, InputSpans: positions == "enabled"}
				if positions == "padding" {
					options.PaddingObservations = &padding
				}
				if err := bb.SetDecodeOptions(options); err != nil {
					t.Fatal(err)
				}
				var msg rrc.ULDCCHMessage
				if err := msg.UnmarshalUPERFrom(bb); err != nil {
					t.Fatal(err)
				}
				if _, err := uper.CaptureFinalBits(bb, "ULDCCHMessage"); err != nil {
					t.Fatal(err)
				}
				records := recovered.Snapshot()
				if len(records) != 1 {
					t.Fatalf("records=%+v", records)
				}
				r := records[0]
				t.Logf("path=%s offset=%d length=%d consumed=%d spans=%+v", r.Path, r.Offset, r.DeclaredLength, r.ConsumedBits, r.InputSpans)
				if r.Offset != tc.local || r.DeclaredLength != tc.length || r.ConsumedBits != tc.consumed || r.Kind != uper.ToleratedIncompleteExtension || !errors.Is(r.Err, uper.ErrTruncated) {
					t.Fatalf("record=%+v", r)
				}
				wantPath := "ULDCCHMessage.Message.C1.UeInformationResponseR9.CriticalExtensions.C1.UeInformationResponseR9.RlfReportR9."
				if tc.local == 118 {
					wantPath += "ExtData_[3]"
				} else {
					wantPath += "LocationInfoR10.ExtData_[0]"
				}
				if r.Path != wantPath {
					t.Fatalf("path=%q want %q", r.Path, wantPath)
				}
				want := uper.InputBitSpan{Offset: tc.input, BitLength: 8 + 8*tc.length}
				if positions == "disabled" {
					if len(r.InputSpans) != 0 {
						t.Fatalf("unrequested spans=%+v", r.InputSpans)
					}
				} else if len(r.InputSpans) != 1 || r.InputSpans[0] != want {
					t.Fatalf("spans=%+v want %+v", r.InputSpans, want)
				}
				for bit := 0; bit < want.BitLength; bit++ {
					got := (data[(tc.input+bit)/8] >> uint(7-(tc.input+bit)%8)) & 1
					source := byte(tc.length)
					if bit >= 8 {
						source = r.Bits.Bytes[(bit-8)/8]
					}
					expected := (source >> uint(7-bit%8)) & 1
					if got != expected {
						t.Fatalf("bit %d=%d want %d", bit, got, expected)
					}
				}
				replay, err := msg.MarshalUPER()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(replay, data) {
					t.Fatalf("replay=%x want %x", replay, data)
				}
			})
		}
	}
}
