// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/raw_json_test.go; SHA-256 39912da57388f8778ff68d764dc04084bc1c6056dd9f4eebddb238b3a2ee0ce1.
package runtime_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"runtime"
	"testing"

	maprt "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

func TestRawJSONIdentifier(t *testing.T) {
	for _, wire := range [][]byte{{5, 0}, {0x63, 2, 5, 0}, {0xdf, 0x81, 0, 1, 0}, {0xbf, 31, 2, 5, 0}} {
		data, err := json.Marshal(hex.EncodeToString(wire))
		if err != nil {
			t.Fatal(err)
		}
		value := maprt.RawValue{Class: 3, Tag: 999, Constructed: true}
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		tag, _, err := ber.DecodeTag(wire)
		if err != nil || value.Class != int(tag.Class) || value.Tag != tag.Number || value.Constructed != tag.Constructed || !reflect.DeepEqual(value.Bytes, wire) {
			t.Fatalf("JSON identifier = %+v, want %s: %v", value, tag, err)
		}
		before := value
		for _, malformed := range []string{`"1f"`, `"1f801f"`, `"1f8180808080808080801f"`, `"1f818080808080808080801f"`, `"1f00"`, `"1f1e"`, `"1fffffffffffffffffffffffffffff7f"`, `"zz"`} {
			if err := json.Unmarshal([]byte(malformed), &value); err == nil || !reflect.DeepEqual(value, before) {
				t.Fatalf("malformed identifier published: %s: %+v %v", malformed, value, err)
			}
		}
	}
}

func TestRawJSONGrowth(t *testing.T) {
	for _, size := range []int{64, 4096, 65536} {
		wire, err := ber.EncodeOctetString(bytes.Repeat([]byte{0x2a}, size))
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(hex.EncodeToString(wire))
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		var value maprt.RawValue
		err = json.Unmarshal(data, &value)
		runtime.ReadMemStats(&after)
		if err != nil || value.Tag != 4 || !bytes.Equal(value.Bytes, wire) {
			t.Fatalf("size %d: raw JSON value: %v", size, err)
		}
		if used := after.TotalAlloc - before.TotalAlloc; used > uint64(5*len(data)+64<<10) {
			t.Fatalf("size %d: retained work allocated %d bytes", size, used)
		}
	}
}
