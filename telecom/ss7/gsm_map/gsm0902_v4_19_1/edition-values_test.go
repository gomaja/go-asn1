// Code generated from the synthetic historical MAP codec contract. DO NOT EDIT.

package gsm0902_v4_19_1

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

//go:embed edition-values.json
var editionValues []byte

func TestEditionSyntheticValues(t *testing.T) {
	var rows []struct {
		Record    int
		Kind      string
		Code      int64
		OldType   string `json:"old_type"`
		Role      string `json:"source_role"`
		Hex       string
		Confirmed bool
		Expected  any
	}
	if err := json.Unmarshal(editionValues, &rows); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	confirmed := 0
	unconfirmed := 0
	for _, row := range rows {
		t.Run(fmt.Sprintf("%03d-%s-%d-%s", row.Record, row.Kind, row.Code, row.Role), func(t *testing.T) {
			var binding *MacroType
			if row.Kind == "error" {
				info, ok := LookupMacroError(row.Code)
				if !ok {
					t.Fatal("missing source error")
				}
				binding = info.Parameter
			} else {
				info, ok := LookupMacroOperation(row.Code)
				if !ok {
					t.Fatal("missing source operation")
				}
				if row.Kind == "invoke" {
					binding = info.Argument
				} else if row.Kind == "result" {
					if !info.ResultPresent {
						t.Fatal("lost RESULT presence")
					}
					binding = info.Result
				} else {
					t.Fatal("unknown synthetic role")
				}
			}
			if binding == nil || binding.ASN1Name != row.OldType {
				t.Fatalf("wrong source type: binding=%+v expected=%s", binding, row.OldType)
			}
			wire, err := hex.DecodeString(row.Hex)
			if err != nil {
				t.Fatal(err)
			}
			value, err := binding.DecodeBER(wire)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if row.Confirmed {
				actual, err := json.Marshal(typedSemantic(t, reflect.ValueOf(value)))
				if err != nil {
					t.Fatal(err)
				}
				expected, err := json.Marshal(semanticKeys(row.Expected))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, expected) {
					t.Fatalf("decoded typed fields differ from the independent semantic oracle for record %d", row.Record)
				}
			}
			replay, err := binding.EncodeBER(value)
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay mismatch: %v", err)
			}
			// Build a new graph from public typed fields only. Private replay state,
			// raw values, unknown additions and wire-form fields cannot contribute.
			fresh := freshTypedFields(t, reflect.ValueOf(value))
			encoded, err := binding.EncodeBER(fresh.Interface(), ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("typed fresh encoding mismatch: %v", err)
			}
			decodedAgain, err := binding.DecodeBER(encoded, ber.WithoutReplayCapture())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fresh.Interface(), freshTypedFields(t, reflect.ValueOf(decodedAgain)).Interface()) {
				t.Fatal("typed fields changed on fresh encoding")
			}
			if row.Confirmed {
				confirmed++
				counts[row.Kind+"/"+row.Role]++
			} else {
				unconfirmed++
				if row.Record != 137 && row.Record != 138 {
					t.Fatal("unexpected unconfirmed row")
				}
				v, ok := value.(BERValue[bool])
				if !ok {
					t.Fatalf("BOOLEAN grammar parameter is %T", value)
				}
				t.Logf("source BOOLEAN grammar accepted; value=%t; procedure comment forbids it above version 1", v.Value)
			}
		})
	}
	if confirmed != 151 || unconfirmed != 2 {
		t.Fatalf("confirmed=%d unconfirmed=%d", confirmed, unconfirmed)
	}
	t.Logf("151 independent-source-confirmed rows: %v; 2 additional grammar BOOLEAN probes", counts)
}

func freshTypedFields(t *testing.T, v reflect.Value) reflect.Value {
	t.Helper()
	if v.Type().Name() == "RawValue" {
		t.Fatalf("opaque source part: %s", v.Type())
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(freshTypedFields(t, v.Elem()))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		t.Fatalf("untyped source part: %s", v.Type())
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			if f.Tag.Get("asn1") == "-" {
				if !v.Field(i).IsZero() {
					t.Fatalf("opaque or form metadata present: %s.%s", v.Type(), f.Name)
				}
				continue
			}
			out.Field(i).Set(freshTypedFields(t, v.Field(i)))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(freshTypedFields(t, v.Index(i)))
		}
		return out
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.String:
		return v
	}
	t.Fatalf("unsupported typed part: %s", v.Type())
	return reflect.Value{}
}

func TestEditionNativeCatalogue(t *testing.T) {
	if len(MacroOperations()) != 46 || len(MacroErrors()) != 38 {
		t.Fatal("incomplete native catalogue")
	}
	// GSM 09.02 V4.19.1 §14.6.1 Reset omits RESULT; §14.6.4
	// UnstructuredSS-Notify prints an empty RESULT. Q.773 §3.1 keeps both.
	absent, ok := LookupMacroOperation(37)
	if !ok || absent.Definition != "Reset" || absent.ResultPresent || absent.Result != nil {
		t.Fatalf("absent RESULT=%+v", absent)
	}
	empty, ok := LookupMacroOperation(61)
	if !ok || empty.Definition != "UnstructuredSS-Notify" || !empty.ResultPresent || empty.Result != nil {
		t.Fatalf("empty RESULT=%+v", empty)
	}
	linked, ok := LookupMacroOperation(17)
	if !ok || len(linked.Linked) != 1 {
		t.Fatalf("LINKED list=%+v", linked)
	}
	request, ok := LookupMacroOperation(60)
	if !ok || request.Argument.ASN1Name != "USSD-Arg" || request.Result.ASN1Name != "USSD-Res" || len(request.Errors) != 8 {
		t.Fatal("approved operation binding lost")
	}
}

func TestEditionProfileCitation(t *testing.T) {
	binding := newMacroType("MAP-CommonDataTypes", "IMSI", "IMSI", IMSICodec())
	wire := []byte{4, 0x81, 3, 0x12, 0x34, 0x56}
	_, err := binding.DecodeBER(wire)
	var refusal *ber.ValidationError
	if !errors.As(err, &refusal) || refusal.Rule.Document != "GSM 09.02" || refusal.Rule.Edition != "V4.19.1" || refusal.Rule.Clause != "14.1.1" {
		t.Fatalf("strict historical profile=%v", err)
	}
	var log ber.ViolationLog
	value, err := binding.DecodeBER(wire, ber.WithTolerance(&log))
	if err != nil {
		t.Fatal(err)
	}
	if records := log.Snapshot(); len(records) != 1 || records[0].Rule.Document != "GSM 09.02" || records[0].Rule.Clause != "14.1.1" {
		t.Fatalf("historical profile records=%+v", records)
	}
	if _, err := binding.EncodeBER(value); !errors.As(err, &refusal) || refusal.Rule.Document != "GSM 09.02" {
		t.Fatalf("strict historical replay=%v", err)
	}
	log.Reset()
	got, err := binding.EncodeBER(value, ber.WithTolerance(&log))
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("historical replay=%v", err)
	}
	if rows := log.Snapshot(); len(rows) != 1 || rows[0].Rule.Document != "GSM 09.02" {
		t.Fatalf("historical encode records=%+v", rows)
	}
}

// Source identifiers and Go field names differ in hyphens/acronym case only.
func semanticName(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, name)
}
func semanticKeys(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for name, part := range v {
			out[semanticName(name)] = semanticKeys(part)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, part := range v {
			out[i] = semanticKeys(part)
		}
		return out
	default:
		return value
	}
}
func typedSemantic(t *testing.T, v reflect.Value) any {
	t.Helper()
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		if strings.HasPrefix(v.Type().Name(), "BERValue[") {
			return typedSemantic(t, v.FieldByName("Value"))
		}
		if v.Type().Name() == "BitString" {
			return map[string]any{"bits": hex.EncodeToString(v.FieldByName("Bytes").Bytes()), "bitlength": v.FieldByName("BitLength").Int()}
		}
		if values := v.FieldByName("Values"); values.IsValid() {
			return typedSemantic(t, values)
		}
		if v.NumField() == 0 {
			return nil
		}
		out := map[string]any{}
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if !field.IsExported() || field.Name == "Choice" || field.Tag.Get("asn1") == "-" {
				continue
			}
			part := v.Field(i)
			if part.Kind() == reflect.Pointer && part.IsNil() {
				continue
			}
			out[semanticName(field.Name)] = typedSemantic(t, part)
		}
		return out
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return map[string]any{"octets": hex.EncodeToString(v.Bytes())}
		}
		out := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = typedSemantic(t, v.Index(i))
		}
		return out
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"integer": v.Int()}
	case reflect.Bool:
		return v.Bool()
	case reflect.String:
		return v.String()
	}
	t.Fatalf("no independent semantic projection for %s", v.Type())
	return nil
}
