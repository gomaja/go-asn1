package gsm_map

import (
	"encoding/hex"
	"math/big"
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

func asn1ContractBigInt(t testing.TB, value string) *big.Int {
	t.Helper()
	decoded, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("invalid generated decimal integer %q", value)
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

// TestContractGsmMapLocalErrorName verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.5; named MAP local error codes retain their standards names.
// Regression: go-asn1-v0.4.2.gsm-map.local-error-named-helper
func TestContractGsmMapLocalErrorName(t *testing.T) {
	t.Parallel()
	value := GSMMAPLocalErrorcodeUnknownSubscriberValue()
	if got := value.String(); got != "unknownSubscriber" {
		t.Fatalf("String() = %q, want %q", got, "unknownSubscriber")
	}
}

// TestContractMapErrorLocalCode verifies 3GPP TS 29.002 V19.1.0 (2026-02), section 17.5; MAP-ERROR localValue helper preserves its exact code.
// Regression: go-asn1-v0.4.2.gsm-map.map-error-local-code-helper
func TestContractMapErrorLocalCode(t *testing.T) {
	t.Parallel()
	value := NewMAPERRORLocalValueInt64(6)
	if value.Choice != MAPERRORChoiceLocalValue {
		t.Fatalf("Choice = %d, want MAPERRORChoiceLocalValue", value.Choice)
	}
	code, ok := value.LocalCode()
	if !ok || code != 6 {
		t.Fatalf("LocalCode() = %d, %t, want 6, true", code, ok)
	}
}

// TestContractErrorCodeLocalCode verifies ITU-T Q.773 (06/1997), section 3.7; TCAP-compatible local error code helper preserves its exact code.
// Regression: go-asn1-v0.4.2.gsm-map.error-code-local-code-helper
func TestContractErrorCodeLocalCode(t *testing.T) {
	t.Parallel()
	value := NewErrorCodeLocalValueInt64(34)
	if value.Choice != ErrorCodeChoiceLocalValue {
		t.Fatalf("Choice = %d, want ErrorCodeChoiceLocalValue", value.Choice)
	}
	code, ok := value.LocalCode()
	if !ok || code != 34 {
		t.Fatalf("LocalCode() = %d, %t, want 34, true", code, ok)
	}
}

// TestContractErrorCodeWideLocalValue verifies ITU-T X.680 (02/2021), clause 19; unconstrained INTEGER values remain arbitrary-width.
// Regression: go-asn1-v0.4.2.gsm-map.error-code-wide-local-value
func TestContractErrorCodeWideLocalValue(t *testing.T) {
	t.Parallel()
	value := NewErrorCodeLocalValue(asn1ContractBigInt(t, "1208925819614629174706176"))
	if value.Choice != ErrorCodeChoiceLocalValue {
		t.Fatalf("Choice = %d, want ErrorCodeChoiceLocalValue", value.Choice)
	}
	code, ok := value.LocalCode()
	if ok {
		t.Fatalf("LocalCode() = %d, true, want false", code)
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
