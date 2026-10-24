package validation

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/lppa"
	lppaaper "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"github.com/gomaja/go-asn1/telecom/lte/rrc"
	"github.com/gomaja/go-asn1/telecom/lte/rrc/runtime/uper"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
	s1aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	"github.com/gomaja/go-asn1/telecom/lte/x2ap"
	x2aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	umts "github.com/gomaja/go-asn1/telecom/umts/rrc"
)

type trainingRecord struct {
	Hex, ID, Type, Expected, LibraryResult, Issue string
	PaddedBITStringContaining                     json.RawMessage `json:"padded_bit_string_containing"`
	TrailingBitsAfterBasicProduction              json.RawMessage `json:"trailing_bits_after_basic_production"`
}

// GO_ASN1_TRAINING_DATA points to local, potentially production-derived test
// inputs. No input octets are included in test diagnostics.
func TestLocalTrainingData(t *testing.T) {
	root := os.Getenv("GO_ASN1_TRAINING_DATA")
	if root == "" {
		t.Skip("GO_ASN1_TRAINING_DATA is unset")
	}
	files := []string{
		"utran/inter-rat-handover-info.jsonl",
		"lte/ue-eutra-capability-nonzero-padding.jsonl",
		"lte/rrc-open-type-padding.jsonl",
		"lte/rrc-trailing-extension-truncated.jsonl",
		"lte/synthetic-s1ap-x2ap-lppa.jsonl",
	}
	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			})
			stats := struct{ Records, Matches, Changed int }{}
			var mismatches []string
			scanner := bufio.NewScanner(file)
			scanner.Buffer(make([]byte, 4096), 16<<20)
			for scanner.Scan() {
				stats.Records++
				var rec trainingRecord
				if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
					t.Fatal(err)
				}
				wire, err := hex.DecodeString(rec.Hex)
				if err != nil {
					t.Fatal(err)
				}
				matched, changed, reason := checkTrainingRecord(name, rec, wire)
				if matched {
					stats.Matches++
				} else {
					mismatches = append(mismatches, fmt.Sprintf("record %d (%s): %s", stats.Records, rec.ID, reason))
				}
				if changed {
					stats.Changed++
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			t.Logf("records=%d matches=%d mismatches=%d changes_vs_old=%d", stats.Records, stats.Matches, len(mismatches), stats.Changed)
			for _, mismatch := range mismatches {
				t.Error(mismatch)
			}
		})
	}
}

func checkTrainingRecord(file string, rec trainingRecord, wire []byte) (bool, bool, string) {
	if strings.HasPrefix(file, "utran/") {
		var value umts.InterRATHandoverInfo
		option := len(rec.PaddedBITStringContaining) != 0 || len(rec.TrailingBitsAfterBasicProduction) != 0 ||
			(strings.HasSuffix(rec.Issue, "/59") && strings.Contains(rec.Expected, "receiver tolerance"))
		var err error
		var tolerated per.ToleranceLog
		if option {
			err = value.UnmarshalUPERWithOptions(wire, per.DecodeOptions{TrailingBitsTolerance: &tolerated})
		} else {
			err = value.UnmarshalUPER(wire)
		}
		if err != nil {
			return false, false, err.Error()
		}
		encoded, err := value.MarshalUPER()
		if err != nil || !bytes.Equal(wire, encoded) {
			return false, false, fmt.Sprintf("round trip: %v", err)
		}
		if option {
			reported := map[per.ToleranceKind]int{}
			for _, record := range tolerated.Snapshot() {
				reported[record.Kind] += record.Bits.BitLength
			}
			if len(rec.PaddedBITStringContaining) != 0 || strings.Contains(rec.Expected, "6 padding bits reported") {
				p := value.V390NonCriticalExtensions.Present.V3a0NonCriticalExtensions.LaterNonCriticalExtensions.InterRATHandoverInfoR3AddExtPERPadding_
				count := p.Trailing().BitLength
				if count == 0 || reported[per.ToleratedContainedBits] != count {
					return false, false, "contained bits were not reported"
				}
			}
			if trailing := value.PERPadding_.Trailing().BitLength; len(rec.TrailingBitsAfterBasicProduction) != 0 && (trailing == 0 || reported[per.ToleratedTrailingBits] != trailing) {
				return false, false, "top-level trailing bits were not reported"
			}
		}
		return true, option && !strings.HasPrefix(rec.LibraryResult, "ok"), ""
	}
	if strings.Contains(file, "ue-eutra-capability") {
		var value rrc.UEEUTRACapability
		if err := value.UnmarshalUPER(wire); err != nil {
			return false, false, err.Error()
		}
		encoded, err := value.MarshalUPER()
		if err != nil || !bytes.Equal(encoded, wire) {
			return false, false, fmt.Sprintf("round trip: %v", err)
		}
		_, count := value.PERPadding_.Bits()
		return count > 0, count > 0, "final padding was not reported"
	}
	if strings.Contains(file, "rrc-open-type-padding") {
		var value rrc.ULDCCHMessage
		if err := value.UnmarshalUPER(wire); err != nil {
			return false, false, err.Error()
		}
		encoded, err := value.MarshalUPER()
		if err != nil || !bytes.Equal(encoded, wire) {
			return false, false, fmt.Sprintf("round trip: %v", err)
		}
		return true, false, ""
	}
	if strings.Contains(file, "rrc-trailing-extension-truncated") {
		var value rrc.ULDCCHMessage
		err := value.UnmarshalUPER(wire)
		return errors.Is(err, uper.ErrTruncated), false, fmt.Sprintf("strict error = %v", err)
	}
	if rec.ID == "s1ap-63-cause-zero-padding" || rec.ID == "s1ap-63-cause-nonzero-padding" {
		var value s1ap.Cause
		report, err := value.UnmarshalAPER(wire)
		if strings.Contains(rec.ID, "nonzero") {
			// X.691 (02/2021) §11.1.4 requires zero complete-value padding.
			var located *s1aper.DecodeError
			return errors.Is(err, s1aper.ErrSyntax) && errors.As(err, &located) && located.Rule.Clause == "§11.1.4" && located.Location.HasWireLocation && len(report.Deviations) == 1, true, fmt.Sprintf("strict Cause padding error=%v", err)
		}
		if err != nil {
			return false, false, err.Error()
		}
		encoded, err := value.MarshalAPER()
		return err == nil && bytes.Equal(encoded, wire) && len(value.ReceivedForm().Padding()) == 0, true, fmt.Sprintf("Cause replay error=%v", err)
	}
	if strings.HasPrefix(rec.ID, "s1ap-") {
		var value s1ap.S1APPDU
		report, err := value.UnmarshalAPER(wire)
		if rec.ID == "s1ap-61-timetowait-nonzero-padding" || rec.ID == "s1ap-61-cause-nonzero-padding" {
			// X.691 (02/2021) §11.1.4 also applies inside each known open value.
			var located *s1aper.DecodeError
			return errors.Is(err, s1aper.ErrSyntax) && errors.As(err, &located) && located.Rule.Clause == "§11.1.4" && located.Location.HasWireLocation && len(report.Deviations) == 1, true, fmt.Sprintf("strict known-value padding error=%v", err)
		}
		wantError := strings.Contains(rec.Expected, "Extra octets should be reported") || strings.HasPrefix(rec.Expected, "Rejected")
		if wantError {
			return errors.Is(err, s1aper.ErrExtraData), !strings.Contains(rec.LibraryResult, "reject"), fmt.Sprintf("typed decode error=%v", err)
		}
		if err != nil {
			return false, false, err.Error()
		}
		encoded, err := value.MarshalAPER()
		return err == nil && bytes.Equal(encoded, wire), false, fmt.Sprintf("typed replay error=%v", err)
	}
	if strings.HasPrefix(rec.ID, "x2ap-") {
		var value x2ap.X2APPDU
		_, err := value.UnmarshalAPER(wire)
		if rec.ID == "x2ap-61-timetowait-nonzero-padding" {
			// Strict decoding refuses non-zero terminal padding in a complete
			// value (ITU-T X.691 (02/2021) §11.1.4). The record's acceptance
			// predates that policy.
			return errors.Is(err, x2aper.ErrSyntax), true, fmt.Sprintf("strict padding error = %v", err)
		}
		wantError := strings.Contains(rec.Expected, "Extra octets should be reported") || strings.HasPrefix(rec.Expected, "Rejected")
		if wantError {
			return errors.Is(err, x2aper.ErrExtraData), !strings.Contains(rec.LibraryResult, "reject"), fmt.Sprintf("typed X2AP decode error = %v", err)
		}
		if err != nil {
			return false, false, err.Error()
		}
		if encoded, err := value.MarshalAPER(); err != nil || !bytes.Equal(encoded, wire) {
			return false, false, "typed X2AP replay failed"
		}
		if rec.ID == "x2ap-62-ue-history-information" {
			if value.InitiatingMessage == nil {
				return false, false, "typed handover missing"
			}
			body, ok := value.InitiatingMessage.Value.AsHandoverRequest()
			if !ok {
				return false, false, "typed HandoverRequest missing"
			}
			found := false
			for i := range body.ProtocolIEs {
				history, ok := x2ap.HandoverRequestIEs().UEHistoryInformation().Get(&body.ProtocolIEs[i])
				if ok && len(*history) != 0 {
					found = true
				}
			}
			if !found {
				return false, false, "typed UE history missing"
			}
			data, jsonErr := json.Marshal(value)
			if jsonErr != nil || bytes.Contains(data, []byte("PERPadding_")) {
				return false, false, "JSON includes padding bookkeeping"
			}
		}
		return true, true, ""
	}
	if strings.HasPrefix(rec.ID, "lppa-") {
		// The typed decoder decodes every known IE value in the same pass.
		var value lppa.LPPAPDU
		_, err := value.UnmarshalAPER(wire)
		if rec.ID == "lppa-61-reportcharacteristics-nonzero-padding" {
			// Strict decoding refuses non-zero terminal padding in a complete
			// value (ITU-T X.691 (02/2021) §11.1.4). The record's acceptance
			// predates that policy.
			return errors.Is(err, lppaaper.ErrSyntax), true, fmt.Sprintf("strict padding error = %v", err)
		}
		return checkSyntheticDispatch(rec, err, lppaaper.ErrExtraData)
	}
	return false, false, "unrecognized training record"
}

func checkSyntheticDispatch(rec trainingRecord, err, extraData error) (bool, bool, string) {
	wantError := strings.Contains(rec.Expected, "Extra octets should be reported") || strings.HasPrefix(rec.Expected, "Rejected")
	if wantError {
		return errors.Is(err, extraData), !strings.Contains(rec.LibraryResult, "reject"), fmt.Sprintf("dispatch error = %v", err)
	}
	return err == nil, false, fmt.Sprintf("dispatch error = %v", err)
}
