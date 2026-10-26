// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bufio "bufio"
	bytes "bytes"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	json "encoding/json"
	fmt "fmt"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	os "os"
	testing "testing"
)

func TestReplayCaptureAllocationBounds(t *testing.T) {
	path := os.Getenv("ASN1_X2AP_CAPTURE")
	if path == "" {
		t.Skip("external capture not supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "9f2c5a113015acbea9f28cb9d06e8e30d9d83472d0f68f684f1674d67a4856a6" {
		t.Fatal("capture hash mismatch")
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 65536), 8<<20)
	var inputs [][]byte
	for scan.Scan() {
		var record struct {
			Hex string `json:"pdu_hex"`
		}
		if err := json.Unmarshal(scan.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		wire, err := hex.DecodeString(record.Hex)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, wire)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 7935 {
		t.Fatalf("records=%d", len(inputs))
	}
	decode := testing.AllocsPerRun(1, func() {
		for _, wire := range inputs {
			replayBoundNeed(replayBoundCaptureDecode(wire))
		}
	})
	values := make([]s19.X2APPDU, len(inputs))
	for i, wire := range inputs {
		replayBoundNeed(replayBoundEnvelopeDecode(&values[i], wire))
	}
	encode := testing.AllocsPerRun(1, func() {
		for i := range values {
			wire, err := values[i].MarshalAPER()
			replayBoundNeed(err)
			if !bytes.Equal(wire, inputs[i]) {
				panic("capture replay mismatch")
			}
		}
	})
	t.Logf("records=%d decode=%v encode=%v", len(inputs), decode, encode)
	if decode > 292261 || encode > 7935 {
		t.Fatalf("capture allocation bounds exceeded: decode=%v encode=%v", decode, encode)
	}
}
