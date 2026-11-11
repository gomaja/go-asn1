// Code generated from the source edition value contract. DO NOT EDIT.
package gsm0902_v3_11_0

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
)

//go:embed edition-values.json
var editionValues []byte

func editionRole(kind string, code int64, role string, assigned bool) *MacroType {
	if !assigned {
		entries := UnassignedMacroOperations()
		if len(entries) != 1 {
			return nil
		}
		if role == "argument" {
			return entries[0].Argument
		}
		return entries[0].Result
	}
	if kind == "ERROR" {
		v, ok := LookupMacroError(code)
		if ok {
			return v.Parameter
		}
		return nil
	}
	v, ok := LookupMacroOperation(code)
	if !ok {
		return nil
	}
	if role == "argument" {
		return v.Argument
	}
	return v.Result
}
func TestEditionEveryNativeRole(t *testing.T) {
	var fixture struct {
		TypedRoles int `json:"typed_roles"`
		Absent     []struct {
			Kind     string
			Code     int64
			Role     string
			Assigned bool
		} `json:"absent_roles"`
		Rows []struct {
			ID, Kind, Role, Definition string
			Code                       int64
			Assigned                   bool
			SourceModule               string `json:"source_module"`
			SourceType                 string `json:"source_type"`
			Hex                        string
			Expected                   any
			Confirmed                  bool `json:"oracle_mapping"`
		}
	}
	if err := json.Unmarshal(editionValues, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.TypedRoles != 80 || len(fixture.Absent) != 67 || len(fixture.Rows) != 160 {
		t.Fatal("incomplete native role fixtures")
	}
	seen := map[string]int{}
	for _, row := range fixture.Rows {
		t.Run(row.ID, func(t *testing.T) {
			binding := editionRole(row.Kind, row.Code, row.Role, row.Assigned)
			if binding == nil || binding.Module != row.SourceModule || binding.ASN1Name != row.SourceType {
				t.Fatal("code-to-type binding differs from source")
			}
			wire, err := hex.DecodeString(row.Hex)
			if err != nil {
				t.Fatal(err)
			}
			value, err := binding.DecodeBER(wire)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(semanticKeys(typedSemantic(t, reflect.ValueOf(value))))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := json.Marshal(semanticKeys(row.Expected))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("typed fields differ from source/independent value mapping: got %s want %s", actual, expected)
			}
			replay, err := binding.EncodeBER(value)
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("exact replay: %v", err)
			}
			fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
			encoded, err := binding.EncodeBER(fresh, ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("fresh typed encoding: %v", err)
			}
			if !row.Confirmed {
				t.Fatal("missing independent value mapping")
			}
			seen[fmt.Sprintf("%s/%d/%s/%t", row.Kind, row.Code, row.Role, row.Assigned)]++
		})
	}
	if len(seen) != 80 {
		t.Fatal("missing typed native role")
	}
	for _, n := range seen {
		if n != 2 {
			t.Fatal("missing minimum/optional role value")
		}
	}
	for _, row := range fixture.Absent {
		if editionRole(row.Kind, row.Code, row.Role, row.Assigned) != nil {
			t.Fatal("absent source role acquired a codec")
		}
	}
	if len(MacroOperations()) != 53 || len(MacroErrors()) != 39 {
		t.Fatal("incomplete code catalogue")
	}
	missing := UnassignedMacroOperations()
	if len(missing) != 1 || missing[0].Name != "DeregisterMobileSubscriber" || missing[0].Module != "MAP-Operations" || missing[0].Argument == nil || !missing[0].ResultPresent {
		t.Fatal("unassigned declaration differs")
	}
	for i, name := range []string{"AbsentSubscriber", "UnknownSubscriber", "FacilityNotSupported", "UnexpectedDataValue"} {
		if !missing[0].ErrorsPresent || len(missing[0].Errors) != 4 || missing[0].LinkedPresent || len(missing[0].Linked) != 0 {
			t.Fatal("unassigned reference lists differ")
		}
		reference := missing[0].Errors[i]
		if reference.Name != name || reference.Definition != name || reference.Module != "MAP-Errors" || reference.DefinitionModule != "MAP-Errors" || reference.IsValue {
			t.Fatal("unassigned error binding differs")
		}
	}
	t.Logf("native declaration role slots=147 typed=80 absent=67 independent values=160; coded slots=145")
}
func freshTypedFields(t *testing.T, v reflect.Value) reflect.Value {
	t.Helper()
	if v.Type() == reflect.TypeFor[runtime.GeneralizedTime]() {
		return v
	}
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
	if v.Type() == reflect.TypeFor[runtime.GeneralizedTime]() {
		return v.Interface().(runtime.GeneralizedTime).String()
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Type() == reflect.TypeFor[runtime.GeneralizedTime]() {
		return v.Interface().(runtime.GeneralizedTime).String()
	}
	switch v.Kind() {
	case reflect.Struct:
		switch value := v.Interface().(type) {
		case SearchForMobileSubscriberArgumentStoredLocationArea:
			if value.Choice == SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1 {
				return map[string]any{"alternative1": nil}
			}
		case UpdateLocationAreaArgumentPreviousLocAreaId:
			if value.Choice == UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1 {
				return map[string]any{"alternative1": nil}
			}
		}
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

func FuzzEditionNativeRole(f *testing.F) {
	var fixture struct {
		Rows []struct {
			Kind, Role, Hex string
			Code            int64
			Assigned        bool
		}
	}
	if err := json.Unmarshal(editionValues, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, row := range fixture.Rows {
		wire, err := hex.DecodeString(row.Hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(row.Kind, row.Code, row.Role, row.Assigned, wire)
	}
	f.Fuzz(func(t *testing.T, kind string, code int64, role string, assigned bool, wire []byte) {
		if len(wire) > 1<<20 {
			return
		}
		binding := editionRole(kind, code, role, assigned)
		if binding == nil {
			return
		}
		value, err := binding.DecodeBER(wire)
		if err != nil {
			return
		}
		got, err := binding.EncodeBER(value)
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("accepted value failed exact replay: %v", err)
		}
		if _, err = binding.EncodeBER(freshTypedFields(t, reflect.ValueOf(value)).Interface(), ber.WithoutBERReplay()); err != nil {
			t.Fatalf("accepted typed fields cannot encode fresh: %v", err)
		}
	})
}

func TestEditionGeneralizedTimeRules(t *testing.T) {
	var fixture struct {
		Rows []struct {
			Definition, Kind, Role, Hex string
			Code                        int64
			Assigned                    bool
		}
	}
	if err := json.Unmarshal(editionValues, &fixture); err != nil {
		t.Fatal(err)
	}
	var charging *MacroType
	var chargingWire []byte
	for _, row := range fixture.Rows {
		if row.Definition == "RegisterChargingInformation" && row.Role == "argument" {
			var err error
			chargingWire, err = hex.DecodeString(row.Hex)
			if err != nil {
				t.Fatal(err)
			}
			charging = editionRole(row.Kind, row.Code, row.Role, row.Assigned)
			break
		}
	}
	if charging == nil || len(chargingWire) == 0 {
		t.Fatal("charging argument control missing")
	}
	for _, row := range []struct {
		text    string
		lexical bool
		clause  string
	}{
		{"198511062106Z", true, ""}, {"19851106210627", true, ""}, {"19851106210627.12345678Z", true, ""}, {"19851106210627.123456789Z", true, ""},
		{"19851106210627+01", false, "ISO 4031:1978 §3"}, {"19851106210627+0100", true, ""},
		{"19851106210627-05", false, "ISO 4031:1978 §3"}, {"19851106210627-0500", true, ""},
		{"19851106210627.3", true, ""}, {"19851106210627,3Z", true, ""}, {"1985110621.5Z", true, ""}, {"198511062106.5Z", true, ""},
		{"20161231235960Z", false, "ISO 3307:1975 §2.5"}, {"20161231235960.5Z", false, "ISO 3307:1975 §2.5"},
		{"19851106240000Z", false, ""}, {"19851106210661Z", false, ""}, {"19851106210627z", false, ""},
	} {
		t.Run(row.text, func(t *testing.T) {
			assertTimeError := func(path string, err error) {
				t.Helper()
				if row.clause == "" {
					return
				}
				var failure *ber.ValidationError
				if !errors.As(err, &failure) {
					t.Errorf("%s: missing time violation: %v", path, err)
					return
				}
				if failure.Path != path || failure.Kind != ber.ASN1Constraint || failure.Rule != (ber.RuleRef{Document: "CCITT X.208", Edition: "11/1988", Clause: "32.3"}) || failure.ObservedValue != row.text || !strings.Contains(failure.Constraint, row.clause) {
					t.Errorf("%s: wrong time violation: %+v", path, failure.Violation)
				}
				if want := path + " value " + row.text + " violates " + failure.Constraint; err.Error() != want {
					t.Errorf("time error text: got %q want %q", err, want)
				}
			}
			valid := row.lexical && len(row.text) >= 14 && len(row.text) <= 24
			wire := append([]byte{24, byte(len(row.text))}, row.text...)
			decoded, err := UnmarshalBERCallDateTime(wire)
			if (err == nil) != valid {
				t.Errorf("strict decode: %v", err)
			}
			assertTimeError("CallDateTime", err)
			if row.clause != "" {
				var failure *ber.ValidationError
				if !errors.As(err, &failure) || failure.Rule.Edition != "11/1988" || failure.Rule.Clause != "32.3" || !strings.Contains(failure.Constraint, row.clause) {
					t.Errorf("historical time diagnostic: %v", err)
				}
			}
			argumentWire, replacements := replaceEditionTime(t, chargingWire, row.text)
			if replacements != 1 {
				t.Fatal("charging time replacement count", replacements)
			}
			_, chargingErr := charging.DecodeBER(argumentWire)
			if (chargingErr == nil) != valid {
				t.Errorf("charging argument strict decode: %v", chargingErr)
			}
			assertTimeError("callDateTime", chargingErr)
			value, parseErr := runtime.ParseGeneralizedTime(row.text)
			if parseErr != nil {
				if err == nil {
					t.Error("unrepresentable lexical form accepted")
				}
				return
			}
			var chargingReports ber.ViolationLog
			chargingTolerant, chargingErr := charging.DecodeBER(argumentWire, ber.WithTolerance(&chargingReports))
			if e := chargingErr; e != nil {
				t.Errorf("charging argument tolerant decode: %v", e)
			} else if !valid && len(chargingReports.Snapshot()) == 0 {
				t.Error("charging argument missing tolerance report")
			}

			if row.clause != "" {
				rows := chargingReports.Snapshot()
				if len(rows) != 1 {
					t.Fatalf("charging reports: %+v", rows)
				}
				assertTimeError("callDateTime", &ber.ValidationError{Violation: rows[0]})
				_, e := charging.EncodeBER(chargingTolerant)
				assertTimeError("callDateTime", e)
			}
			var reports ber.ViolationLog
			tolerant, e := UnmarshalBERCallDateTime(wire, ber.WithTolerance(&reports))
			if e != nil {
				t.Fatalf("representable tolerant decode: %v", e)
			}
			if !valid {
				rows := reports.Snapshot()
				if len(rows) == 0 {
					t.Fatal("missing tolerance report")
				}
				if row.clause != "" {
					if len(rows) != 1 {
						t.Fatalf("root reports: %+v", rows)
					}
					assertTimeError("CallDateTime", &ber.ValidationError{Violation: rows[0]})
				}
				if _, e = MarshalBERCallDateTime(tolerant); e == nil {
					t.Error("strict replay accepted source violation")
				}
				assertTimeError("CallDateTime", e)
			}
			encoded, e := MarshalBERCallDateTime(&BERValue[CallDateTime]{Value: value})
			if (e == nil) != valid {
				t.Errorf("fresh encode: %v", e)
			}
			assertTimeError("CallDateTime", e)
			if row.clause != "" {
				var log ber.ViolationLog
				_, e = MarshalBERCallDateTime(&BERValue[CallDateTime]{Value: value}, ber.WithTolerance(&log))
				assertTimeError("CallDateTime", e)
				if len(log.Snapshot()) != 0 {
					t.Error("fresh tolerant encoder recorded a time violation")
				}
				_, e = MarshalDERCallDateTime(&BERValue[CallDateTime]{Value: value})
				assertTimeError("CallDateTime", e)
			}
			if valid {
				replay, e := MarshalBERCallDateTime(decoded)
				if e != nil || !bytes.Equal(replay, wire) || !bytes.Equal(encoded, wire) {
					t.Errorf("time replay/fresh bytes: %v", e)
				}
			}
			argument := RegisterChargingInformationArgument{MsIsdn: []byte{0}, MscNumber: []byte{0}, Imsi: []byte{0, 0}, CallReference: []byte{0}, CallType: 0, CallStatus: 0, CallDateTime: value, CallDuration: 0}
			_, e = argument.MarshalBER()
			if (e == nil) != valid {
				t.Errorf("charging argument encode: %v", e)
			}
			assertTimeError("callDateTime", e)
			var encodeLog ber.ViolationLog
			_, e = argument.MarshalBER(ber.WithTolerance(&encodeLog))
			if (e == nil) != valid {
				t.Errorf("tolerant charging encode bypassed time rule: %v", e)
			}
			assertTimeError("callDateTime", e)
			if row.clause != "" {
				if len(encodeLog.Snapshot()) != 0 {
					t.Error("fresh charging encoder recorded a time violation")
				}
				_, e = argument.MarshalDER()
				assertTimeError("callDateTime", e)
			}
		})
	}
}

func TestEditionNativeCatalogue(t *testing.T) {
	native, err := os.ReadFile("NATIVE-MACROS.json")
	if err != nil {
		t.Fatal(err)
	}
	type reference struct {
		Module, DefinitionModule struct{ Name string }
		Name, Definition         string
		IsValue                  bool
	}
	var inventory struct {
		Bindings []struct {
			Definition struct {
				Kind, Name                   string
				ErrorsPresent, LinkedPresent bool
				Result                       struct{ Present bool }
			}
			DefinitionModule struct{ Name string }
			Value            struct{ Name, Local string }
			Errors, Linked   []reference
		}
	}
	if err = json.Unmarshal(native, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Bindings) != 92 {
		t.Fatal("incomplete source catalogue")
	}
	compare := func(got []MacroReference, want []reference) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatal("reference list length")
		}
		for i, r := range want {
			g := got[i]
			if g.Module != r.Module.Name || g.Name != r.Name || g.DefinitionModule != r.DefinitionModule.Name || g.Definition != r.Definition || g.IsValue != r.IsValue {
				t.Fatal("reference identity")
			}
		}
	}
	for _, row := range inventory.Bindings {
		code, err := strconv.ParseInt(row.Value.Local, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if row.Definition.Kind == "OPERATION" {
			v, ok := LookupMacroOperation(code)
			if !ok || v.Name != row.Value.Name || v.Definition != row.Definition.Name || v.Module != row.DefinitionModule.Name || v.ErrorsPresent != row.Definition.ErrorsPresent || v.LinkedPresent != row.Definition.LinkedPresent || v.ResultPresent != row.Definition.Result.Present {
				t.Fatal("source operation identity")
			}
			compare(v.Errors, row.Errors)
			compare(v.Linked, row.Linked)
		} else {
			v, ok := LookupMacroError(code)
			if !ok || v.Name != row.Value.Name || v.Definition != row.Definition.Name || v.Module != row.DefinitionModule.Name {
				t.Fatal("source error identity")
			}
		}
	}
}

func TestEditionPasswordUnion(t *testing.T) {
	for _, row := range []struct {
		text  string
		valid bool
	}{{"1234", true}, {"12", true}, {"12345", true}, {"12 4", true}, {"", true}, {"  ", false}, {"1 2 3", false}} {
		wire := append([]byte{18, byte(len(row.text))}, row.text...)
		var value Password
		if err := value.UnmarshalBER(wire); (err == nil) != row.valid {
			t.Errorf("Password union decode %q: %v", row.text, err)
		}
		fresh := Password{Choice: PasswordChoiceAlternative1, Alternative1: &row.text}
		if _, err := fresh.MarshalBER(); (err == nil) != row.valid {
			t.Errorf("Password union encode %q: %v", row.text, err)
		}
	}
}

func TestEditionTruncationMutants(t *testing.T) {
	var fixture struct {
		Rows []struct {
			Kind, Role, Hex string
			Code            int64
			Assigned        bool
		}
	}
	if err := json.Unmarshal(editionValues, &fixture); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range fixture.Rows {
		wire, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		binding := editionRole(row.Kind, row.Code, row.Role, row.Assigned)
		for n := 0; n < len(wire); n++ {
			if _, err := binding.DecodeBER(wire[:n]); err == nil {
				t.Fatalf("truncated native role accepted: %s/%d/%s at %d", row.Kind, row.Code, row.Role, n)
			}
			count++
		}
	}
	t.Logf("strict truncation mutants=%d", count)
}

// X.208 (11/1988) §32.3 assigns universal tag 24 to GeneralizedTime.
// Rebuild only the time contents in an independently encoded argument.
func replaceEditionTime(t *testing.T, wire []byte, text string) ([]byte, int) {
	t.Helper()
	valueTag, n, value, err := ber.DecodeTLV(wire)
	if err != nil || n != len(wire) {
		t.Fatal("invalid control TLV", err)
	}
	if valueTag.Class == 0 && valueTag.Number == 24 {
		encoded, err := ber.EncodeTLV(valueTag, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return encoded, 1
	}
	if !valueTag.Constructed {
		return wire, 0
	}
	var children []byte
	count := 0
	for offset := 0; offset < len(value); {
		_, n, _, err := ber.DecodeTLV(value[offset:])
		if err != nil || n <= 0 {
			t.Fatal("invalid control child", err)
		}
		child, changed := replaceEditionTime(t, value[offset:offset+n], text)
		children = append(children, child...)
		count += changed
		offset += n
	}
	encoded, err := ber.EncodeTLV(valueTag, children)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, count
}

func TestEditionCallDateTimeSize(t *testing.T) {
	for _, text := range []string{"198511062106Z", "19851106210627", "19851106210627.12345678Z", "19851106210627.123456789Z"} {
		valid := len(text) >= 14 && len(text) <= 24
		wire := append([]byte{24, byte(len(text))}, text...)
		_, err := UnmarshalBERCallDateTime(wire)
		if (err == nil) != valid {
			t.Errorf("SIZE decode %d: %v", len(text), err)
		}
		value, e := runtime.ParseGeneralizedTime(text)
		if e != nil {
			t.Fatal(e)
		}
		_, err = MarshalBERCallDateTime(&BERValue[CallDateTime]{Value: value})
		if (err == nil) != valid {
			t.Errorf("SIZE encode %d: %v", len(text), err)
		}
		var encodeLog ber.ViolationLog
		_, err = MarshalBERCallDateTime(&BERValue[CallDateTime]{Value: value}, ber.WithTolerance(&encodeLog))
		if (err == nil) != valid {
			t.Errorf("tolerant SIZE encode %d: %v", len(text), err)
		}
	}
}
