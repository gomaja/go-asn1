// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bufio "bufio"
	bytes "bytes"
	sha256 "crypto/sha256"
	hex "encoding/hex"
	json "encoding/json"
	fmt "fmt"
	os "os"
	testing "testing"
)

// External inputs include production-derived records. Only IDs, hashes and
// measured upper bounds are retained here; their octets stay outside the module.
func TestReplayInputAllocationBounds(t *testing.T) {
	path := os.Getenv("ASN1_X2AP_ALLOCATION_INPUTS")
	if path == "" {
		t.Skip("external allocation corpus not supplied")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	inputs := map[string]replayBoundInput{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		var row replayBoundInput
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		inputs[row.ID] = row
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id, sha256     string
		decode, encode float64
	}{
		{id: "wire/x2ap/handover-request/envelope/x2ap/capture.pcap:1", sha256: "e3a3a48fc3f7e8cba84e36958f019637087a8802825194ed8f6ce72eda403eac", decode: 47, encode: 1},
		{id: "x2ap-62-ue-history-information", sha256: "7cb8a013aeaaae07336991d1a2e2189c270a265b2f05c240e09fed7fce3cfd70", decode: 12, encode: 1},
		{id: "x2ap-61-baseline", sha256: "d35b5db159c64126d8d9e4cce4ece576cdcc4a43853d6df991a5550b197a296c", decode: 11, encode: 1},
		{id: "handover-request-ue-history-recursive", sha256: "e3a3a48fc3f7e8cba84e36958f019637087a8802825194ed8f6ce72eda403eac", decode: 47, encode: 1},
		{id: "handover-request-ue-history-ie-15", sha256: "2de064fdf8017a508b2bc340b4e33dd325835a977709636f2f9d8bb316023da1", decode: 5, encode: 1},
		{id: "protocol-ie-field-header", sha256: "ed34a7f76b3d9760219ef4f9bba876fb5d7ad4102c62005ecd708941bab0d9aa", decode: 1, encode: 1},
		{id: "handover-request-nine-visited-cells", sha256: "03f791ae60928fa54fc97093120762c90e088ab504a257732c60cc66603a1f0d", decode: 35, encode: 1},
		{id: "handover-request-old-enb-ue-id", sha256: "2ecd8a6b7d2845546659ad4cf443533cf921b19dc81fa83934e83821b4dfdcb7", decode: 1, encode: 1},
		{id: "erab-setup-item-recursive-ie", sha256: "764adb2f32eee91b7ba7671f0fbc400f53794721ebb5938d98877674346fd82c", decode: 14, encode: 1},
		{id: "nrra-report-recursive", sha256: "22fce5a3b0882a06e1d9e5824d7530d02abbe91a835d38f1a985731abf018d40", decode: 7, encode: 1},
		{id: "erab-setup-private-ie-preserved", sha256: "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953", decode: 1, encode: 1},
		{id: "erab-setup-daps-extension-recursive", sha256: "b320085d0bce352f115ac0516a8752aec8d222e375eb9eb754f1f5656d2e39a8", decode: 15, encode: 1},
		{id: "successful-outcome-daps-extension-recursive", sha256: "0b630ee7e1a97ca5be8e7f9f89c087ba3e81996e82b7b31ee47d69587f19ac96", decode: 26, encode: 1},
		{id: "admitted-item-unknown-extension-field", sha256: "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953", decode: 1, encode: 1},
		{id: "admitted-item-daps-extension-value", sha256: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", decode: 1, encode: 1},
		{id: "erab-setup-unknown-extension-preserved", sha256: "27515f0b10f44a66e07eea6e5e72fb6a2b86c90924d6c3e5ae62b7974352a43c", decode: 13, encode: 1},
	}
	for _, row := range rows {
		t.Run(row.id, func(t *testing.T) {
			input, ok := inputs[row.id]
			if !ok {
				t.Fatal("missing pinned input")
			}
			raw, err := hex.DecodeString(input.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != row.sha256 {
				t.Fatal("input hash mismatch")
			}
			op, wire := replayBoundMakeOps(input, raw)
			decode := testing.AllocsPerRun(10, func() { replayBoundNeed(op.decode()) })
			encode := testing.AllocsPerRun(10, func() {
				out, err := op.encode()
				replayBoundNeed(err)
				if !bytes.Equal(out, wire) {
					panic("replay mismatch")
				}
			})
			t.Logf("decode=%v <= %v; encode=%v <= %v", decode, row.decode, encode, row.encode)
			if decode > row.decode || encode > row.encode {
				t.Fatalf("allocation bounds exceeded: decode=%v encode=%v", decode, encode)
			}
		})
	}
}
