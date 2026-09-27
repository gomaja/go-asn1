package umts_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	lterrc "github.com/gomaja/go-asn1/telecom/lte/rrc"
	umtsrrc "github.com/gomaja/go-asn1/telecom/umts/rrc"
)

type localTraceEvent struct {
	EventName string `json:"event_name"`
	PDUHex    string `json:"pdu_hex"`
}

// TestLocalUECapabilityTrace checks the TS 36.331 V19.3.0 clause 6.3.6
// UTRA container rule against TS 25.331 V19.0.1 clause 11.2
// InterRATHandoverInfo. The trace is supplied only at test time.
func TestLocalUECapabilityTrace(t *testing.T) {
	path := os.Getenv("GO_ASN1_UMTS_TRACE_JSON")
	if path == "" {
		t.Skip("GO_ASN1_UMTS_TRACE_JSON is unset")
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("trace file is absent")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close trace: %v", err)
		}
	}()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	var events, utra, geranCS, geranPS int
	for scanner.Scan() {
		var event localTraceEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("trace JSON: %v", err)
		}
		if event.EventName != "UECapabilityInformation" {
			continue
		}
		events++
		wire, err := hex.DecodeString(event.PDUHex)
		if err != nil {
			t.Fatalf("event %d hex: %v", events, err)
		}
		var message lterrc.ULDCCHMessage
		if err := message.UnmarshalUPER(wire); err != nil {
			t.Fatalf("event %d LTE decode: %v", events, err)
		}
		if message.Message.C1 == nil || message.Message.C1.UeCapabilityInformation == nil {
			t.Fatalf("event %d has no UE capability information", events)
		}
		capability := message.Message.C1.UeCapabilityInformation
		if capability.CriticalExtensions.C1 == nil || capability.CriticalExtensions.C1.UeCapabilityInformationR8 == nil {
			t.Fatalf("event %d has no r8 UE capability", events)
		}
		for _, container := range capability.CriticalExtensions.C1.UeCapabilityInformationR8.UeCapabilityRATContainerList {
			switch container.RatType {
			case lterrc.RATTypeUtra:
				utra++
				var info umtsrrc.InterRATHandoverInfo
				if err := info.UnmarshalUPER(container.UeCapabilityRATContainer); err != nil {
					t.Fatalf("event %d UTRA %d decode: %v", events, utra, err)
				}
				if info.UeCapabilityContainer.Choice != umtsrrc.InterRATHandoverInfoUeCapabilityContainerChoicePresent || info.UeCapabilityContainer.Present == nil {
					t.Fatalf("event %d UTRA %d did not decode the typed UE capability", events, utra)
				}
				encoded, err := info.MarshalUPER()
				if err != nil {
					t.Fatalf("event %d UTRA %d encode: %v", events, utra, err)
				}
				if !bytes.Equal(encoded, container.UeCapabilityRATContainer) {
					t.Fatalf("event %d UTRA %d byte-exact mismatch: input=%d output=%d bytes", events, utra, len(container.UeCapabilityRATContainer), len(encoded))
				}
			case lterrc.RATTypeGeranCs:
				geranCS++
			case lterrc.RATTypeGeranPs:
				geranPS++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if events != 2389 || utra != 2389 || geranCS != 7 || geranPS != 7 {
		t.Fatalf("unexpected trace counts: events=%d UTRA=%d GERAN-CS=%d GERAN-PS=%d", events, utra, geranCS, geranPS)
	}
	t.Logf("events=%d UTRA decoded and byte-exact=%d GERAN-CS=%d GERAN-PS=%d", events, utra, geranCS, geranPS)
}
