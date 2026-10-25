// Code generated from the pinned X2AP vector inventory. DO NOT EDIT.
package x2ap

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type selectedCoverageUnion interface{ Selected() (any, bool) }

func selectedCoverageWalk(t *testing.T, v reflect.Value, unions, rows map[string]bool) {
	t.Helper()
	if !v.IsValid() {
		return
	}
	if v.Kind() == reflect.Interface {
		if !v.IsNil() {
			selectedCoverageWalk(t, v.Elem(), unions, rows)
		}
		return
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return
	}
	candidate := v
	if v.Kind() != reflect.Pointer && v.CanAddr() {
		candidate = v.Addr()
	}
	if candidate.CanInterface() {
		if u, ok := candidate.Interface().(selectedCoverageUnion); ok {
			typ := candidate.Type().String()
			unions[typ] = true
			got, found := u.Selected()
			var want any
			selected := ""
			for i := 0; i < candidate.NumMethod(); i++ {
				m := candidate.Type().Method(i)
				if !strings.HasPrefix(m.Name, "As") {
					continue
				}
				r := candidate.Method(i).Call(nil)
				if r[1].Bool() {
					want = r[0].Interface()
					selected = m.Name
					break
				}
			}
			if found != (want != nil) || got != want {
				t.Fatalf("%s Selected differs from As", typ)
			}
			if found {
				rows[typ+"."+selected] = true
				selectedCoverageWalk(t, reflect.ValueOf(got), unions, rows)
			}
			return
		}
	}
	if v.Kind() == reflect.Pointer {
		selectedCoverageWalk(t, v.Elem(), unions, rows)
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				selectedCoverageWalk(t, v.Field(i), unions, rows)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			selectedCoverageWalk(t, v.Index(i), unions, rows)
		}
	}
}
func TestSelectedDecodedCoverage(t *testing.T) {
	unions, rows := map[string]bool{}, map[string]bool{}
	{
		wire, err := hex.DecodeString("0000007b000006000a00020001000540020000000b00080021f35412345670001700070021f354000101000e004100010000000000000000000000000000000000000000000000000000000000000000000000000000010001000004400e4500060401f0c000020100000001020000000f400c000021f35412345670000005")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := X2APPDUCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
	}
	{
		wire, err := hex.DecodeString("000021f35412345670000005")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := UEHistoryInformationCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
		field, err := HandoverRequestIEs().UEHistoryInformation().New(value.Value)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&field), unions, rows)
	}
	{
		wire, err := hex.DecodeString("800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := UEHistoryInformationCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
		field, err := HandoverRequestIEs().UEHistoryInformation().New(value.Value)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&field), unions, rows)
	}
	{
		wire, err := hex.DecodeString("0007")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := UEX2APIDCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
		field, err := HandoverRequestIEs().OldENBUEX2APID().New(value.Value)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&field), unions, rows)
	}
	{
		wire, err := hex.DecodeString("4500060701f00afd0055037806f5")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := ERABsToBeSetupItemCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
		field, err := ERABsToBeSetupItemIEs().ERABsToBeSetupItem().New(value.Value)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&field), unions, rows)
	}
	{
		wire, err := hex.DecodeString("000001019e4009000006040000000000")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := AccessAndMobilityIndicationCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
	}
	{
		wire, err := hex.DecodeString("2500093c03e00a000001deadbeef0000016b400100")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := ERABsToBeSetupItemCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
	}
	{
		wire, err := hex.DecodeString("000027000004000a400200070009400200080001400e000000400912800000016e000100000c400201aa")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := SuccessfulOutcomeCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
	}
	{
		wire, err := hex.DecodeString("00")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := DAPSResponseInfoCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
		field, err := ERABsAdmittedItemExtIEs().DAPSResponseInfo().New(value.Value)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&field), unions, rows)
	}
	{
		wire, err := hex.DecodeString("2500093c03e00a000001deadbeef0000fffc4004deadbeef")
		if err != nil {
			t.Fatal(err)
		}
		value, _, err := ERABsToBeSetupItemCodec().DecodeAPER(wire)
		if err != nil {
			t.Fatal(err)
		}
		selectedCoverageWalk(t, reflect.ValueOf(&value.Value), unions, rows)
	}
	if len(rows) == 0 {
		t.Fatal("vectors reached no typed rows")
	}
	t.Logf("synthetic decoded coverage: unions=%d/481 rows=%d/1054; unreached unions=%d rows=%d", len(unions), len(rows), 481-len(unions), 1054-len(rows))
	if path := os.Getenv("ASN1_X2AP_CAPTURE"); path != "" {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 65536), 8<<20)
		accepted, refused := 0, 0
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
			var v X2APPDU
			if _, err := v.UnmarshalAPER(wire); err != nil {
				refused++
				continue
			}
			accepted++
			selectedCoverageWalk(t, reflect.ValueOf(&v), unions, rows)
		}
		if err := scan.Err(); err != nil {
			t.Fatal(err)
		}
		t.Logf("capture accepted=%d refused=%d", accepted, refused)
	}
	t.Logf("combined decoded coverage: unions=%d/481 rows=%d/1054; unreached unions=%d rows=%d", len(unions), len(rows), 481-len(unions), 1054-len(rows))
}
