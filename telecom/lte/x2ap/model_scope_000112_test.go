// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	sha256 "crypto/sha256"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	os "os"
	testing "testing"
)

func TestFragmentedNestedReplayAfterScalarEdit(t *testing.T) {
	payload := make([]byte, 65540)
	for i := range payload {
		payload[i] = byte(i*13 + 7)
	}
	header := s05.RNLHeader{SourceGlobalENBID: s05.GlobalENBID{PLMNIdentity: []byte{1, 2, 3}, ENBID: eNBIDapiMust(s00.NewENBIDMacroENBID(runtime.BitString{Bytes: []byte{0, 0, 0}, BitLength: 20}))}}
	table := s13.X2APMessageTransferIEs()
	body := x2APMessageTransferapiMust(s21.NewX2APMessageTransfer(s13.X2APMessageTransferIEContainer{x2APMessageTransferIEFieldapiMust(table.RNLHeader().New(header)), x2APMessageTransferIEFieldapiMust(table.X2APMessage().New(payload))}))
	envelope := initiatingMessageapiMust(s21.X2APMessageTransferProcedure().Initiating().Build(body))
	pdu := x2APPDUapiMust(s21.NewX2APPDUInitiatingMessage(envelope))
	wire := listByteapiMust(pdu.MarshalAPER())
	t.Logf("synthetic carrier size=%d sha256=%x", len(wire), sha256.Sum256(wire))
	if got := fmt.Sprintf("%x", sha256.Sum256(wire)); got != "f49b0db4a5b50d02ab51e7d1e620d6605d9a9d66c6bf95974c92fe293fa37982" {
		t.Fatalf("independent carrier encoding changed: %s", got)
	}
	if path := os.Getenv("X2AP_SYNTHETIC_FRAGMENT_OUT"); path != "" {
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var value s20.X2APPDU
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	decoded, ok := value.InitiatingMessage.Value.AsX2APMessageTransfer()
	if !ok {
		t.Fatal("lost typed carrier")
	}
	if len(decoded.ProtocolIEs[1].ReceivedForm().Location().Spans) < 2 {
		t.Fatal("fragmented field lost physical spans")
	}
	receivedHeader, ok := decoded.ProtocolIEs[0].Value.AsRNLHeader()
	if !ok {
		t.Fatal("lost typed RNL header")
	}
	receivedHeader.SourceGlobalENBID.PLMNIdentity[0] = 9
	changed := listByteapiMust(value.MarshalAPER())
	var next s20.X2APPDU
	if _, err := next.UnmarshalAPER(changed); err != nil {
		t.Fatal(err)
	}
	nextBody, _ := next.InitiatingMessage.Value.AsX2APMessageTransfer()
	contents, ok := nextBody.ProtocolIEs[1].Value.AsX2APMessage()
	if !ok || !bytes.Equal(*contents, payload) {
		t.Fatal("scalar edit changed untouched fragmented payload")
	}
	receivedHeader.SourceGlobalENBID.PLMNIdentity[0] = 1
	if !bytes.Equal(listByteapiMust(value.MarshalAPER()), wire) {
		t.Fatal("restored fragmented carrier did not replay")
	}
}
