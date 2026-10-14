package gsm_map

import (
	"encoding/hex"
	"strings"
	"testing"
)

func asn1ContractHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestContractAlertServiceCentreIndefiniteDerRejection verifies ITU-T X.690 (02/2021), clauses 8.1.3.6 and 10.1; DER forbids indefinite length encodings at every preserved nested value.
// Regression: go-asn1-v0.4.2.gsm-map.indefinite-der-rejection
func TestContractAlertServiceCentreIndefiniteDerRejection(t *testing.T) {
	t.Parallel()
	input := asn1ContractHex(t, "300c040101040102aa8005000000")
	var value AlertServiceCentreArg
	if err := value.UnmarshalBER(input); err != nil {
		t.Fatal(err)
	}
	_, err := value.MarshalDER()
	if err == nil {
		t.Fatal("operation succeeded, want error")
	}
	if !strings.Contains(err.Error(), "indefinite length not allowed in DER") {
		t.Fatalf("error = %q, want substring %q", err, "indefinite length not allowed in DER")
	}
}

// TestContractAllocationRetentionPriorityNilInteger verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.7.1; mandatory unconstrained INTEGER values reject an unset value before encoding.
// Regression: go-asn1-v0.4.2.gsm-map.nil-priority-level-validation
func TestContractAllocationRetentionPriorityNilInteger(t *testing.T) {
	t.Parallel()
	var value AllocationRetentionPriority
	_, err := value.MarshalBER()
	if err == nil {
		t.Fatal("operation succeeded, want error")
	}
	if !strings.Contains(err.Error(), "priority-level") {
		t.Fatalf("error = %q, want substring %q", err, "priority-level")
	}
}
