// Code generated from the historical edition validation contract. DO NOT EDIT.
package gsm0902_v4_19_1

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"os"
	"reflect"
	"strconv"
	"testing"
)

//go:embed edition-formal.json
var editionFormal []byte

//go:embed NATIVE-MACROS.json
var editionNative []byte

//go:embed edition-encoding.json
var editionEncoding []byte

type editionProbe struct {
	ID, Module, Type, Family, Hex, Source string
	Valid, Tolerant                       bool
	Expected                              any
}

func editionEncodingProbes(t testing.TB) []editionProbe {
	t.Helper()
	var rows []editionProbe
	if err := json.Unmarshal(editionEncoding, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 11 {
		t.Fatal("incomplete encoding-rule probes")
	}
	return rows
}
func editionProbes(t testing.TB) []editionProbe {
	t.Helper()
	var f struct {
		Types int
		Rows  []editionProbe
	}
	if err := json.Unmarshal(editionFormal, &f); err != nil {
		t.Fatal(err)
	}
	if f.Types != 157 || len(f.Rows) == 0 {
		t.Fatal("incomplete formal fixture")
	}
	return f.Rows
}
func editionSemanticEqual(t *testing.T, value, expected any) {
	t.Helper()
	actual, e := json.Marshal(semanticKeys(typedSemantic(t, reflect.ValueOf(value))))
	if e != nil {
		t.Fatal(e)
	}
	wanted, e := json.Marshal(semanticKeys(expected))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, wanted) {
		t.Fatal("typed fields differ from independent formal semantics")
	}
}

func TestEditionFormalProbes(t *testing.T) {
	bindings := editionNamedTypes()
	visited := map[string]bool{}
	families := map[string]int{}
	valid, invalid := 0, 0
	for _, row := range editionProbes(t) {
		t.Run(row.ID, func(t *testing.T) {
			key := row.Module + "." + row.Type
			binding := bindings[key]
			if binding == nil {
				t.Fatal("formal probe has no typed factory")
			}
			visited[key] = true
			wire, err := hex.DecodeString(row.Hex)
			if err != nil {
				t.Fatal(err)
			}
			value, err := binding.DecodeBER(wire)
			if !row.Valid {
				invalid++
				families[row.Family]++
				if err == nil {
					t.Fatalf("source %s violation accepted (%s)", row.Family, row.Source)
				}
				var reports ber.ViolationLog
				value, e := binding.DecodeBER(wire, ber.WithTolerance(&reports))
				if e != nil || len(reports.Snapshot()) == 0 {
					t.Fatalf("representable deviation lost: %v", e)
				}
				got, e := binding.EncodeBER(value, ber.WithTolerance(&reports))
				if e != nil || !bytes.Equal(got, wire) {
					t.Fatalf("tolerant replay: %v", e)
				}
				fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
				if _, e := binding.EncodeBER(fresh, ber.WithoutBERReplay()); e == nil {
					t.Fatal("fresh source violation accepted")
				}
				return
			}
			valid++
			if err != nil {
				t.Fatalf("valid source probe refused: %v", err)
			}
			editionSemanticEqual(t, value, row.Expected)
			got, err := binding.EncodeBER(value)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("formal replay: %v", err)
			}
			fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
			got, err = binding.EncodeBER(fresh, ber.WithoutBERReplay())
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("formal fresh encoding: %v", err)
			}
		})
	}
	if len(visited) != 157 || len(bindings) != 157 {
		t.Fatalf("formal coverage=%d/%d", len(visited), len(bindings))
	}
	for _, family := range []string{"SIZE", "range", "enumeration", "alphabet"} {
		if families[family] == 0 {
			t.Fatalf("missing %s probes", family)
		}
	}
	t.Logf("formal types=%d valid=%d invalid=%d families=%v", len(visited), valid, invalid, families)
}

func TestEditionTruncationMutants(t *testing.T) {
	count := 0
	bindings := editionNamedTypes()
	for _, row := range editionProbes(t) {
		if !row.Valid {
			continue
		}
		wire, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		binding := bindings[row.Module+"."+row.Type]
		for n := 0; n < len(wire); n++ {
			for _, tolerant := range []bool{false, true} {
				var opts []ber.DecodeOption
				var reports ber.ViolationLog
				if tolerant {
					opts = []ber.DecodeOption{ber.WithTolerance(&reports)}
				}
				if _, err := binding.DecodeBER(wire[:n], opts...); err == nil {
					t.Fatalf("truncated formal value accepted: %s at %d", row.ID, n)
				}
				count++
			}
		}
	}
	if count == 0 {
		t.Fatal("no truncation mutants")
	}
	t.Logf("truncation mutants=%d", count)
}

func TestEditionEncodingRules(t *testing.T) {
	bindings := editionNamedTypes()
	for _, row := range editionEncodingProbes(t) {
		t.Run(row.ID, func(t *testing.T) {
			binding := bindings[row.Module+"."+row.Type]
			if binding == nil {
				t.Fatal("encoding probe lacks source type")
			}
			wire, _ := hex.DecodeString(row.Hex)
			value, err := binding.DecodeBER(wire)
			if (err == nil) != row.Valid {
				t.Fatalf("strict verdict differs from %s: %v", row.Source, err)
			}
			var log ber.ViolationLog
			tolerant, e := binding.DecodeBER(wire, ber.WithTolerance(&log))
			if (e == nil) != (row.Valid || row.Tolerant) {
				t.Fatalf("tolerant verdict differs from %s: %v", row.Source, e)
			}
			if !row.Valid && !row.Tolerant {
				return
			}
			if row.Tolerant {
				if len(log.Snapshot()) == 0 {
					t.Fatal("missing profile finding")
				}
				for _, v := range log.Snapshot() {
					if v.Rule.Document != "GSM 09.02" || v.Rule.Edition != "V4.19.1" || v.Rule.Clause != "14.1.1" {
						t.Fatal("profile citation differs")
					}
				}
				value = tolerant
			}
			opts := []ber.EncodeOption{}
			if row.Tolerant {
				opts = append(opts, ber.WithTolerance(&log))
			}
			got, e := binding.EncodeBER(value, opts...)
			if e != nil || !bytes.Equal(got, wire) {
				t.Fatalf("encoding-rule exact replay: %v", e)
			}
			fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
			encoded, e := binding.EncodeBER(fresh, ber.WithoutBERReplay())
			if e != nil {
				t.Fatalf("fresh profile normalization failed: %v", e)
			}
			if _, e := binding.DecodeBER(encoded); e != nil {
				t.Fatalf("fresh profile not strict: %v", e)
			}
		})
	}
	t.Logf("encoding-rule probes=%d", len(editionEncodingProbes(t)))
}

type editionSourceReference struct {
	Module, DefinitionModule struct{ Name string }
	Name, Definition         string
	IsValue                  bool
}

func editionReferencesEqual(t *testing.T, generated []MacroReference, source []editionSourceReference) {
	t.Helper()
	if len(generated) != len(source) {
		t.Fatal("source reference-list length differs")
	}
	for i, v := range generated {
		r := source[i]
		if v.Module != r.Module.Name || v.DefinitionModule != r.DefinitionModule.Name || v.Name != r.Name || v.Definition != r.Definition || v.IsValue != r.IsValue {
			t.Fatal("source reference-list binding differs")
		}
	}
}
func TestEditionDescriptorCoverage(t *testing.T) {
	var native struct {
		Bindings []struct {
			Definition struct {
				Kind, Name                   string
				ErrorsPresent, LinkedPresent bool
				Result                       struct{ Present bool }
			}
			DefinitionModule            struct{ Name string }
			Value                       struct{ Name, Local string }
			Argument, Result, Parameter *struct {
				Name, Builtin string
				Module        struct{ Name string }
			}
			Errors, Linked []editionSourceReference
		}
	}
	if err := json.Unmarshal(editionNative, &native); err != nil {
		t.Fatal(err)
	}
	probes := editionProbes(t)
	typed, absent, visited := 0, 0, 0
	for _, row := range native.Bindings {
		t.Run(row.Value.Name, func(t *testing.T) {
			code, err := strconv.ParseInt(row.Value.Local, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			var roles []*MacroType
			var sourceNames, sourceModules []string
			if row.Definition.Kind == "OPERATION" {
				v, ok := LookupMacroOperation(code)
				if !ok || v.Name != row.Value.Name || v.Definition != row.Definition.Name || v.Module != row.DefinitionModule.Name || v.ErrorsPresent != row.Definition.ErrorsPresent || v.LinkedPresent != row.Definition.LinkedPresent || v.ResultPresent != row.Definition.Result.Present {
					t.Fatal("source operation descriptor differs")
				}
				editionReferencesEqual(t, v.Errors, row.Errors)
				editionReferencesEqual(t, v.Linked, row.Linked)
				roles = []*MacroType{v.Argument, v.Result}
				for _, r := range []any{row.Argument, row.Result} {
					rv := reflect.ValueOf(r)
					name, module := "", ""
					if !rv.IsNil() {
						rv = rv.Elem()
						name = rv.FieldByName("Name").String()
						module = rv.FieldByName("Module").FieldByName("Name").String()
					}
					sourceNames = append(sourceNames, name)
					sourceModules = append(sourceModules, module)
				}
			} else {
				v, ok := LookupMacroError(code)
				if !ok || v.Name != row.Value.Name || v.Definition != row.Definition.Name || v.Module != row.DefinitionModule.Name {
					t.Fatal("source error descriptor differs")
				}
				roles = []*MacroType{v.Parameter}
				name, module := "", ""
				if row.Parameter != nil {
					name = row.Parameter.Name
					if name == "" {
						name = row.Parameter.Builtin
					}
					module = row.Parameter.Module.Name
				}
				sourceNames = []string{name}
				sourceModules = []string{module}
			}
			for i, binding := range roles {
				visited++
				if sourceNames[i] == "" {
					if binding != nil {
						t.Fatal("formally absent part has a codec")
					}
					absent++
					continue
				}
				if binding == nil || binding.ASN1Name != sourceNames[i] || binding.Module != sourceModules[i] {
					t.Fatal("code-to-source-type binding differs")
				}
				typed++
				var wire []byte
				var expected any
				found := false
				if binding.ASN1Name == "BOOLEAN" {
					wire = []byte{1, 1, 0}
					expected = false
					found = true
				} else {
					for _, probe := range probes {
						if probe.Valid && probe.Module == binding.Module && probe.Type == binding.ASN1Name {
							wire, _ = hex.DecodeString(probe.Hex)
							expected = probe.Expected
							found = true
							break
						}
					}
				}
				if !found {
					t.Fatal("descriptor lacks a typed construction probe")
				}
				value, err := binding.DecodeBER(wire)
				if err != nil {
					t.Fatal(err)
				}
				editionSemanticEqual(t, value, expected)
				fresh := freshTypedFields(t, reflect.ValueOf(value)).Interface()
				got, err := binding.EncodeBER(fresh, ber.WithoutBERReplay())
				if err != nil || !bytes.Equal(got, wire) {
					t.Fatalf("descriptor fresh construction: %v", err)
				}
			}
		})
	}
	if len(native.Bindings) != 84 || visited != 130 {
		t.Fatalf("descriptor census=%d/%d", len(native.Bindings), visited)
	}
	t.Logf("descriptor parts=%d typed=%d formally-absent=%d", visited, typed, absent)
}

func TestEditionSeededEdits(t *testing.T) {
	bindings := editionNamedTypes()
	groups := map[string][]editionProbe{}
	for _, row := range editionProbes(t) {
		if row.Valid {
			key := row.Module + "." + row.Type
			groups[key] = append(groups[key], row)
		}
	}
	edits, originals, noAlternative := 0, 0, 0
	for _, row := range editionProbes(t) {
		if !row.Valid {
			continue
		}
		key := row.Module + "." + row.Type
		peers := groups[key]
		if len(peers) < 2 {
			noAlternative++
			continue
		}
		var peer editionProbe
		for _, candidate := range peers {
			if candidate.Hex != row.Hex {
				peer = candidate
				break
			}
		}
		if peer.ID == "" {
			t.Fatal("distinct value inventory lost")
		}
		binding := bindings[key]
		wire, _ := hex.DecodeString(row.Hex)
		otherWire, _ := hex.DecodeString(peer.Hex)
		original, err := binding.DecodeBER(wire)
		if err != nil {
			t.Fatal(err)
		}
		other, err := binding.DecodeBER(otherWire)
		if err != nil {
			t.Fatal(err)
		}
		source := reflect.ValueOf(original)
		edited := reflect.New(source.Type()).Elem()
		edited.Set(source)
		fresh := freshTypedFields(t, reflect.ValueOf(other))
		for i := 0; i < edited.NumField(); i++ {
			field := edited.Type().Field(i)
			if field.IsExported() && field.Tag.Get("asn1") != "-" {
				edited.Field(i).Set(fresh.Field(i))
			}
		}
		got, err := binding.EncodeBER(edited.Interface())
		if err != nil || !bytes.Equal(got, otherWire) {
			t.Fatalf("retained value did not follow typed edit for %s: %v", row.ID, err)
		}
		decoded, err := binding.DecodeBER(got)
		if err != nil {
			t.Fatal(err)
		}
		editionSemanticEqual(t, decoded, peer.Expected)
		replay, err := binding.EncodeBER(original)
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("typed edit corrupted original replay for %s: %v", row.ID, err)
		}
		edits++
		originals++
	}
	if edits < 100 {
		t.Fatalf("insufficient seeded edits=%d", edits)
	}
	t.Logf("seeded edits=%d exact original replays=%d no distinct source probe=%d", edits, originals, noAlternative)
}

func TestEditionRetainedFormEdits(t *testing.T) {
	t.Run("primitive", func(t *testing.T) {
		wire := []byte{4, 0x81, 3, 0, 0, 0}
		var log ber.ViolationLog
		original, err := IMSICodec().DecodeBER(wire, ber.WithTolerance(&log))
		if err != nil || original.berReplayNode_ == nil {
			t.Fatalf("received form not retained: %v", err)
		}
		edited := original
		edited.Value = append([]byte(nil), original.Value...)
		edited.Value[0] = 1
		got, err := IMSICodec().EncodeBER(edited)
		if err != nil || !bytes.Equal(got, []byte{4, 3, 1, 0, 0}) {
			t.Fatalf("typed primitive edit did not repair the profile: %v", err)
		}
		replay, err := IMSICodec().EncodeBER(original, ber.WithTolerance(&log))
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("original primitive form changed: %v", err)
		}
	})
	t.Run("profile-composite", func(t *testing.T) {
		wire := []byte{0x30, 0x81, 8, 4, 0x81, 1, 0, 4, 2, 0, 0}
		var log ber.ViolationLog
		original, err := USSDArgCodec().DecodeBER(wire, ber.WithTolerance(&log))
		if err != nil || original.berReplayNode_ == nil {
			t.Fatalf("received composite form not retained: %v", err)
		}
		edited := original
		edited.UssdString = append(USSDString(nil), original.UssdString...)
		edited.UssdString[0] = 1
		got, err := USSDArgCodec().EncodeBER(edited, ber.WithTolerance(&log))
		if err != nil {
			t.Fatalf("tolerant typed edit refused: %v", err)
		}
		if _, err := USSDArgCodec().DecodeBER(got, ber.WithTolerance(&log)); err != nil {
			t.Fatal(err)
		}
		got, err = USSDArgCodec().EncodeBER(edited)
		if err != nil || !bytes.Equal(got, []byte{0x30, 7, 4, 1, 0, 4, 2, 1, 0}) {
			t.Fatalf("typed composite edit did not repair the profile: %v", err)
		}
		replay, err := USSDArgCodec().EncodeBER(original, ber.WithTolerance(&log))
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("original composite form changed: %v", err)
		}
	})
	// X.209 (11/1988) §7.2.1 permits any nonzero TRUE octet. Unlike the
	// nonminimal lengths above, this sibling is legal in the edition profile.
	t.Run("unchanged-boolean-sibling", func(t *testing.T) {
		wire := []byte{0x30, 0x80, 0x80, 1, 0, 0x81, 1, 1, 0x82, 1, 0, 0, 0}
		original, err := RoutingInfoForSMArgCodec().DecodeBER(wire)
		if err != nil || original.berReplayNode_ == nil {
			t.Fatalf("legal received form not retained: %v", err)
		}
		edited := original
		edited.ServiceCentreAddress = append(AddressString(nil), original.ServiceCentreAddress...)
		edited.ServiceCentreAddress[0] = 1
		got, err := RoutingInfoForSMArgCodec().EncodeBER(edited)
		if err != nil || !bytes.Contains(got, []byte{0x81, 1, 1}) {
			t.Fatalf("legal unchanged sibling lost: %v", err)
		}
		fresh, err := RoutingInfoForSMArgCodec().EncodeBER(edited, ber.WithoutBERReplay())
		if err != nil || !bytes.Equal(fresh, []byte{0x30, 9, 0x80, 1, 0, 0x81, 1, 0xff, 0x82, 1, 1}) {
			t.Fatalf("fresh boolean canonical form: %v", err)
		}
		replay, err := RoutingInfoForSMArgCodec().EncodeBER(original)
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("original legal form changed: %v", err)
		}
	})
	if !t.Failed() {
		t.Log("retained-form edits=3 exact original replays=3 unchanged siblings=1")
	}
}

func TestEditionOracleObservations(t *testing.T) {
	// The scorecard requests observations explicitly; normal package tests need
	// no external files and never skip. Each projection reads only typed fields.
	out := os.Getenv("MAP_EDITION_OBSERVATIONS")
	if out == "" {
		return
	}
	type observation struct {
		ID               string `json:"id"`
		Decoded          bool   `json:"decoded"`
		Semantic         any    `json:"semantic,omitempty"`
		Error            string `json:"error,omitempty"`
		TolerantDecoded  bool   `json:"tolerant_decoded,omitempty"`
		TolerantSemantic any    `json:"tolerant_semantic,omitempty"`
	}
	var rows []observation
	bindings := editionNamedTypes()
	for _, row := range editionProbes(t) {
		wire, _ := hex.DecodeString(row.Hex)
		v, err := bindings[row.Module+"."+row.Type].DecodeBER(wire)
		o := observation{ID: row.ID, Decoded: err == nil}
		if err != nil {
			o.Error = err.Error()
		} else {
			o.Semantic = semanticKeys(typedSemantic(t, reflect.ValueOf(v)))
		}
		rows = append(rows, o)
	}
	for _, row := range editionEncodingProbes(t) {
		wire, _ := hex.DecodeString(row.Hex)
		binding := bindings[row.Module+"."+row.Type]
		v, err := binding.DecodeBER(wire)
		o := observation{ID: row.ID, Decoded: err == nil}
		if err != nil {
			o.Error = err.Error()
		} else {
			o.Semantic = semanticKeys(typedSemantic(t, reflect.ValueOf(v)))
		}
		if row.Tolerant {
			var log ber.ViolationLog
			v, err = binding.DecodeBER(wire, ber.WithTolerance(&log))
			o.TolerantDecoded = err == nil
			if err == nil {
				o.TolerantSemantic = semanticKeys(typedSemantic(t, reflect.ValueOf(v)))
			}
		}
		rows = append(rows, o)
	}
	var synthetic []struct {
		Record int
		Kind   string
		Code   int64
		Hex    string
	}
	if err := json.Unmarshal(editionValues, &synthetic); err != nil {
		t.Fatal(err)
	}
	for _, row := range synthetic {
		binding := editionRole(row.Kind, row.Code)
		if binding == nil {
			t.Fatal("missing synthetic role")
		}
		wire, _ := hex.DecodeString(row.Hex)
		v, err := binding.DecodeBER(wire)
		o := observation{ID: fmt.Sprintf("synthetic/%d", row.Record), Decoded: err == nil}
		if err != nil {
			o.Error = err.Error()
		} else {
			o.Semantic = semanticKeys(typedSemantic(t, reflect.ValueOf(v)))
		}
		rows = append(rows, o)
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("typed oracle observations=%d", len(rows))
}
func editionRole(kind string, code int64) *MacroType {
	if kind == "error" {
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
	if kind == "invoke" {
		return v.Argument
	}
	if kind == "result" && v.ResultPresent {
		return v.Result
	}
	return nil
}

func TestEditionReferenceEncodings(t *testing.T) {
	input, output := os.Getenv("MAP_EDITION_REFERENCE_ENCODINGS"), os.Getenv("MAP_EDITION_REFERENCE_FINDINGS")
	if input == "" && output == "" {
		return
	}
	if input == "" || output == "" {
		t.Fatal("reference encoding input/output must be paired")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var rows []editionProbe
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	type finding struct {
		ID              string          `json:"id"`
		StrictDecoded   bool            `json:"strict_decoded"`
		TolerantDecoded bool            `json:"tolerant_decoded"`
		Semantic        any             `json:"semantic,omitempty"`
		Reports         []ber.Violation `json:"reports,omitempty"`
	}
	result := []finding{}
	bindings := editionNamedTypes()
	for _, row := range rows {
		binding := bindings[row.Module+"."+row.Type]
		if binding == nil {
			t.Fatal("unknown reference source type")
		}
		wire, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		_, strictErr := binding.DecodeBER(wire)
		var log ber.ViolationLog
		value, tolerantErr := binding.DecodeBER(wire, ber.WithTolerance(&log))
		r := finding{ID: row.ID, StrictDecoded: strictErr == nil, TolerantDecoded: tolerantErr == nil, Reports: log.Snapshot()}
		if tolerantErr == nil {
			r.Semantic = semanticKeys(typedSemantic(t, reflect.ValueOf(value)))
		}
		result = append(result, r)
	}
	data, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("reference fresh encodings=%d", len(result))
}
func editionHasOpaque(v reflect.Value) bool {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return false
		}
		return editionHasOpaque(v.Elem())
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			if f.Tag.Get("asn1") == "-" {
				if !v.Field(i).IsZero() {
					return true
				}
				continue
			}
			if editionHasOpaque(v.Field(i)) {
				return true
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				if editionHasOpaque(v.Index(i)) {
					return true
				}
			}
		}
	}
	return false
}
func editionFuzzValue(t *testing.T, binding *MacroType, wire []byte) {
	t.Helper()
	if binding == nil || len(wire) > 1<<20 {
		return
	}
	value, err := binding.DecodeBER(wire)
	if err != nil {
		return
	}
	got, err := binding.EncodeBER(value)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("strict accepted value did not replay exactly: %v", err)
	}
	if editionHasOpaque(reflect.ValueOf(value)) {
		return
	}
	encoded, err := binding.EncodeBER(value, ber.WithoutBERReplay())
	if err != nil {
		t.Fatalf("accepted typed value could not encode fresh: %v", err)
	}
	again, err := binding.DecodeBER(encoded)
	if err != nil {
		t.Fatalf("fresh typed value refused: %v", err)
	}
	editionSemanticEqual(t, again, typedSemantic(t, reflect.ValueOf(value)))
}
func editionSeedRole(f *testing.F, kind string) {
	var rows []struct {
		Kind string
		Code int64
		Hex  string
	}
	if err := json.Unmarshal(editionValues, &rows); err != nil {
		f.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == kind {
			wire, _ := hex.DecodeString(row.Hex)
			f.Add(row.Code, wire)
		}
	}
	f.Fuzz(func(t *testing.T, code int64, wire []byte) { editionFuzzValue(t, editionRole(kind, code), wire) })
}
func FuzzEditionInvokeArgument(f *testing.F) { editionSeedRole(f, "invoke") }
func FuzzEditionReturnResult(f *testing.F)   { editionSeedRole(f, "result") }
func FuzzEditionErrorParameter(f *testing.F) { editionSeedRole(f, "error") }
func FuzzEditionNamedType(f *testing.F) {
	bindings := editionNamedTypes()
	for _, row := range append(editionProbes(f), editionEncodingProbes(f)...) {
		wire, _ := hex.DecodeString(row.Hex)
		f.Add(row.Module+"."+row.Type, wire)
	}
	f.Add("MAP-DialogueInformation.MAP-AcceptInfo", []byte{0x30, 6, 4, 0x81, 3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, key string, wire []byte) { editionFuzzValue(t, bindings[key], wire) })
}

func editionNamedTypes() map[string]*MacroType {
	return map[string]*MacroType{
		"MobileDomainDefinitions.CommonComponentId":              newMacroType("MobileDomainDefinitions", "CommonComponentId", "CommonComponentId", CommonComponentIdCodec()),
		"MAP-BS-Code.BearerServiceCode":                          newMacroType("MAP-BS-Code", "BearerServiceCode", "BearerServiceCode", BearerServiceCodeCodec()),
		"MAP-TS-Code.TeleserviceCode":                            newMacroType("MAP-TS-Code", "TeleserviceCode", "TeleserviceCode", TeleserviceCodeCodec()),
		"MAP-CommonDataTypes.TBCD-STRING":                        newMacroType("MAP-CommonDataTypes", "TBCD-STRING", "TBCDSTRING", TBCDSTRINGCodec()),
		"MAP-CommonDataTypes.AddressString":                      newMacroType("MAP-CommonDataTypes", "AddressString", "AddressString", AddressStringCodec()),
		"MAP-CommonDataTypes.ISDN-AddressString":                 newMacroType("MAP-CommonDataTypes", "ISDN-AddressString", "ISDNAddressString", ISDNAddressStringCodec()),
		"MAP-CommonDataTypes.ISDN-SubaddressString":              newMacroType("MAP-CommonDataTypes", "ISDN-SubaddressString", "ISDNSubaddressString", ISDNSubaddressStringCodec()),
		"MAP-CommonDataTypes.ExternalSignalInfo":                 newMacroType("MAP-CommonDataTypes", "ExternalSignalInfo", "ExternalSignalInfo", ExternalSignalInfoCodec()),
		"MAP-CommonDataTypes.SignalInfo":                         newMacroType("MAP-CommonDataTypes", "SignalInfo", "SignalInfo", SignalInfoCodec()),
		"MAP-CommonDataTypes.ProtocolId":                         newMacroType("MAP-CommonDataTypes", "ProtocolId", "ProtocolId", ProtocolIdCodec()),
		"MAP-CommonDataTypes.IMSI":                               newMacroType("MAP-CommonDataTypes", "IMSI", "IMSI", IMSICodec()),
		"MAP-CommonDataTypes.TMSI":                               newMacroType("MAP-CommonDataTypes", "TMSI", "TMSI", TMSICodec()),
		"MAP-CommonDataTypes.SubscriberId":                       newMacroType("MAP-CommonDataTypes", "SubscriberId", "SubscriberId", SubscriberIdCodec()),
		"MAP-CommonDataTypes.IMEI":                               newMacroType("MAP-CommonDataTypes", "IMEI", "IMEI", IMEICodec()),
		"MAP-CommonDataTypes.LocationInfo":                       newMacroType("MAP-CommonDataTypes", "LocationInfo", "LocationInfo", LocationInfoCodec()),
		"MAP-CommonDataTypes.HLR-Id":                             newMacroType("MAP-CommonDataTypes", "HLR-Id", "HLRId", HLRIdCodec()),
		"MAP-CommonDataTypes.HLR-List":                           newMacroType("MAP-CommonDataTypes", "HLR-List", "HLRList", HLRListCodec()),
		"MAP-CommonDataTypes.LMSI":                               newMacroType("MAP-CommonDataTypes", "LMSI", "LMSI", LMSICodec()),
		"MAP-CommonDataTypes.GlobalCellId":                       newMacroType("MAP-CommonDataTypes", "GlobalCellId", "GlobalCellId", GlobalCellIdCodec()),
		"MAP-CommonDataTypes.NetworkResource":                    newMacroType("MAP-CommonDataTypes", "NetworkResource", "NetworkResource", NetworkResourceCodec()),
		"MAP-CommonDataTypes.Category":                           newMacroType("MAP-CommonDataTypes", "Category", "Category", CategoryCodec()),
		"MAP-CommonDataTypes.BearerServiceList":                  newMacroType("MAP-CommonDataTypes", "BearerServiceList", "BearerServiceList", BearerServiceListCodec()),
		"MAP-CommonDataTypes.TeleserviceList":                    newMacroType("MAP-CommonDataTypes", "TeleserviceList", "TeleserviceList", TeleserviceListCodec()),
		"MAP-CommonDataTypes.BasicServiceCode":                   newMacroType("MAP-CommonDataTypes", "BasicServiceCode", "BasicServiceCode", BasicServiceCodeCodec()),
		"MAP-CommonDataTypes.BasicServiceList":                   newMacroType("MAP-CommonDataTypes", "BasicServiceList", "BasicServiceList", BasicServiceListCodec()),
		"MAP-CommonDataTypes.BasicServiceGroupList":              newMacroType("MAP-CommonDataTypes", "BasicServiceGroupList", "BasicServiceGroupList", BasicServiceGroupListCodec()),
		"MAP-SS-Code.SS-Code":                                    newMacroType("MAP-SS-Code", "SS-Code", "SSCode", SSCodeCodec()),
		"MAP-SS-DataTypes.RegisterSS-Arg":                        newMacroType("MAP-SS-DataTypes", "RegisterSS-Arg", "RegisterSSArg", RegisterSSArgCodec()),
		"MAP-SS-DataTypes.NoReplyConditionTime":                  newMacroType("MAP-SS-DataTypes", "NoReplyConditionTime", "NoReplyConditionTime", NoReplyConditionTimeCodec()),
		"MAP-SS-DataTypes.SS-Info":                               newMacroType("MAP-SS-DataTypes", "SS-Info", "SSInfo", SSInfoCodec()),
		"MAP-SS-DataTypes.ForwardingInfo":                        newMacroType("MAP-SS-DataTypes", "ForwardingInfo", "ForwardingInfo", ForwardingInfoCodec()),
		"MAP-SS-DataTypes.ForwardingFeatureList":                 newMacroType("MAP-SS-DataTypes", "ForwardingFeatureList", "ForwardingFeatureList", ForwardingFeatureListCodec()),
		"MAP-SS-DataTypes.ForwardingFeature":                     newMacroType("MAP-SS-DataTypes", "ForwardingFeature", "ForwardingFeature", ForwardingFeatureCodec()),
		"MAP-SS-DataTypes.SS-Status":                             newMacroType("MAP-SS-DataTypes", "SS-Status", "SSStatus", SSStatusCodec()),
		"MAP-SS-DataTypes.ForwardingOptions":                     newMacroType("MAP-SS-DataTypes", "ForwardingOptions", "ForwardingOptions", ForwardingOptionsCodec()),
		"MAP-SS-DataTypes.CallBarringInfo":                       newMacroType("MAP-SS-DataTypes", "CallBarringInfo", "CallBarringInfo", CallBarringInfoCodec()),
		"MAP-SS-DataTypes.CallBarringFeatureList":                newMacroType("MAP-SS-DataTypes", "CallBarringFeatureList", "CallBarringFeatureList", CallBarringFeatureListCodec()),
		"MAP-SS-DataTypes.CallBarringFeature":                    newMacroType("MAP-SS-DataTypes", "CallBarringFeature", "CallBarringFeature", CallBarringFeatureCodec()),
		"MAP-SS-DataTypes.CUG-Info":                              newMacroType("MAP-SS-DataTypes", "CUG-Info", "CUGInfo", CUGInfoCodec()),
		"MAP-SS-DataTypes.CUG-SubscriptionList":                  newMacroType("MAP-SS-DataTypes", "CUG-SubscriptionList", "CUGSubscriptionList", CUGSubscriptionListCodec()),
		"MAP-SS-DataTypes.CUG-Subscription":                      newMacroType("MAP-SS-DataTypes", "CUG-Subscription", "CUGSubscription", CUGSubscriptionCodec()),
		"MAP-SS-DataTypes.CUG-Index":                             newMacroType("MAP-SS-DataTypes", "CUG-Index", "CUGIndex", CUGIndexCodec()),
		"MAP-SS-DataTypes.CUG-Interlock":                         newMacroType("MAP-SS-DataTypes", "CUG-Interlock", "CUGInterlock", CUGInterlockCodec()),
		"MAP-SS-DataTypes.IntraCUG-Options":                      newMacroType("MAP-SS-DataTypes", "IntraCUG-Options", "IntraCUGOptions", IntraCUGOptionsCodec()),
		"MAP-SS-DataTypes.CUG-FeatureList":                       newMacroType("MAP-SS-DataTypes", "CUG-FeatureList", "CUGFeatureList", CUGFeatureListCodec()),
		"MAP-SS-DataTypes.CUG-Feature":                           newMacroType("MAP-SS-DataTypes", "CUG-Feature", "CUGFeature", CUGFeatureCodec()),
		"MAP-SS-DataTypes.InterCUG-Restrictions":                 newMacroType("MAP-SS-DataTypes", "InterCUG-Restrictions", "InterCUGRestrictions", InterCUGRestrictionsCodec()),
		"MAP-SS-DataTypes.SS-Data":                               newMacroType("MAP-SS-DataTypes", "SS-Data", "SSData", SSDataCodec()),
		"MAP-SS-DataTypes.SS-SubscriptionOption":                 newMacroType("MAP-SS-DataTypes", "SS-SubscriptionOption", "SSSubscriptionOption", SSSubscriptionOptionCodec()),
		"MAP-SS-DataTypes.CliRestrictionOption":                  newMacroType("MAP-SS-DataTypes", "CliRestrictionOption", "CliRestrictionOption", CliRestrictionOptionCodec()),
		"MAP-SS-DataTypes.OverrideCategory":                      newMacroType("MAP-SS-DataTypes", "OverrideCategory", "OverrideCategory", OverrideCategoryCodec()),
		"MAP-SS-DataTypes.SS-ForBS-Code":                         newMacroType("MAP-SS-DataTypes", "SS-ForBS-Code", "SSForBSCode", SSForBSCodeCodec()),
		"MAP-SS-DataTypes.Cli-RestrictionInfo":                   newMacroType("MAP-SS-DataTypes", "Cli-RestrictionInfo", "CliRestrictionInfo", CliRestrictionInfoCodec()),
		"MAP-SS-DataTypes.InterrogateSS-Res":                     newMacroType("MAP-SS-DataTypes", "InterrogateSS-Res", "InterrogateSSRes", InterrogateSSResCodec()),
		"MAP-SS-DataTypes.SS-UserData":                           newMacroType("MAP-SS-DataTypes", "SS-UserData", "SSUserData", SSUserDataCodec()),
		"MAP-SS-DataTypes.USSD-Arg":                              newMacroType("MAP-SS-DataTypes", "USSD-Arg", "USSDArg", USSDArgCodec()),
		"MAP-SS-DataTypes.USSD-Res":                              newMacroType("MAP-SS-DataTypes", "USSD-Res", "USSDRes", USSDResCodec()),
		"MAP-SS-DataTypes.USSD-DataCodingScheme":                 newMacroType("MAP-SS-DataTypes", "USSD-DataCodingScheme", "USSDDataCodingScheme", USSDDataCodingSchemeCodec()),
		"MAP-SS-DataTypes.USSD-String":                           newMacroType("MAP-SS-DataTypes", "USSD-String", "USSDString", USSDStringCodec()),
		"MAP-SS-DataTypes.Password":                              newMacroType("MAP-SS-DataTypes", "Password", "Password", PasswordCodec()),
		"MAP-SS-DataTypes.GuidanceInfo":                          newMacroType("MAP-SS-DataTypes", "GuidanceInfo", "GuidanceInfo", GuidanceInfoCodec()),
		"MAP-SS-DataTypes.BeginSubscriberActivityArg":            newMacroType("MAP-SS-DataTypes", "BeginSubscriberActivityArg", "BeginSubscriberActivityArg", BeginSubscriberActivityArgCodec()),
		"MAP-SS-DataTypes.SS-List":                               newMacroType("MAP-SS-DataTypes", "SS-List", "SSList", SSListCodec()),
		"MAP-SS-DataTypes.SS-InfoList":                           newMacroType("MAP-SS-DataTypes", "SS-InfoList", "SSInfoList", SSInfoListCodec()),
		"MAP-SS-DataTypes.ForwardingData":                        newMacroType("MAP-SS-DataTypes", "ForwardingData", "ForwardingData", ForwardingDataCodec()),
		"MAP-CH-DataTypes.CUG-CheckInfo":                         newMacroType("MAP-CH-DataTypes", "CUG-CheckInfo", "CUGCheckInfo", CUGCheckInfoCodec()),
		"MAP-CH-DataTypes.NumberOfForwarding":                    newMacroType("MAP-CH-DataTypes", "NumberOfForwarding", "NumberOfForwarding", NumberOfForwardingCodec()),
		"MAP-CH-DataTypes.SendRoutingInfoArg":                    newMacroType("MAP-CH-DataTypes", "SendRoutingInfoArg", "SendRoutingInfoArg", SendRoutingInfoArgCodec()),
		"MAP-CH-DataTypes.SendRoutingInfoRes":                    newMacroType("MAP-CH-DataTypes", "SendRoutingInfoRes", "SendRoutingInfoRes", SendRoutingInfoResCodec()),
		"MAP-CH-DataTypes.RoutingInfo":                           newMacroType("MAP-CH-DataTypes", "RoutingInfo", "RoutingInfo", RoutingInfoCodec()),
		"MAP-CH-DataTypes.ProvideRoamingNumberArg":               newMacroType("MAP-CH-DataTypes", "ProvideRoamingNumberArg", "ProvideRoamingNumberArg", ProvideRoamingNumberArgCodec()),
		"MAP-DialogueInformation.MAP-DialoguePDU":                newMacroType("MAP-DialogueInformation", "MAP-DialoguePDU", "MAPDialoguePDU", MAPDialoguePDUCodec()),
		"MAP-DialogueInformation.MAP-OpenInfo":                   newMacroType("MAP-DialogueInformation", "MAP-OpenInfo", "MAPOpenInfo", MAPOpenInfoCodec()),
		"MAP-DialogueInformation.MAP-AcceptInfo":                 newMacroType("MAP-DialogueInformation", "MAP-AcceptInfo", "MAPAcceptInfo", MAPAcceptInfoCodec()),
		"MAP-DialogueInformation.MAP-CloseInfo":                  newMacroType("MAP-DialogueInformation", "MAP-CloseInfo", "MAPCloseInfo", MAPCloseInfoCodec()),
		"MAP-DialogueInformation.MAP-RefuseInfo":                 newMacroType("MAP-DialogueInformation", "MAP-RefuseInfo", "MAPRefuseInfo", MAPRefuseInfoCodec()),
		"MAP-DialogueInformation.Reason":                         newMacroType("MAP-DialogueInformation", "Reason", "Reason", ReasonCodec()),
		"MAP-DialogueInformation.MAP-UserAbortInfo":              newMacroType("MAP-DialogueInformation", "MAP-UserAbortInfo", "MAPUserAbortInfo", MAPUserAbortInfoCodec()),
		"MAP-DialogueInformation.MAP-UserAbortChoice":            newMacroType("MAP-DialogueInformation", "MAP-UserAbortChoice", "MAPUserAbortChoice", MAPUserAbortChoiceCodec()),
		"MAP-DialogueInformation.ResourceUnavailableReason":      newMacroType("MAP-DialogueInformation", "ResourceUnavailableReason", "ResourceUnavailableReason", ResourceUnavailableReasonCodec()),
		"MAP-DialogueInformation.ProcedureCancellationReason":    newMacroType("MAP-DialogueInformation", "ProcedureCancellationReason", "ProcedureCancellationReason", ProcedureCancellationReasonCodec()),
		"MAP-DialogueInformation.MAP-ProviderAbortInfo":          newMacroType("MAP-DialogueInformation", "MAP-ProviderAbortInfo", "MAPProviderAbortInfo", MAPProviderAbortInfoCodec()),
		"MAP-DialogueInformation.MAP-ProviderAbortReason":        newMacroType("MAP-DialogueInformation", "MAP-ProviderAbortReason", "MAPProviderAbortReason", MAPProviderAbortReasonCodec()),
		"MAP-ER-DataTypes.RoamingNotAllowedCause":                newMacroType("MAP-ER-DataTypes", "RoamingNotAllowedCause", "RoamingNotAllowedCause", RoamingNotAllowedCauseCodec()),
		"MAP-ER-DataTypes.CallBarringCause":                      newMacroType("MAP-ER-DataTypes", "CallBarringCause", "CallBarringCause", CallBarringCauseCodec()),
		"MAP-ER-DataTypes.CUG-RejectCause":                       newMacroType("MAP-ER-DataTypes", "CUG-RejectCause", "CUGRejectCause", CUGRejectCauseCodec()),
		"MAP-ER-DataTypes.SS-IncompatibilityCause":               newMacroType("MAP-ER-DataTypes", "SS-IncompatibilityCause", "SSIncompatibilityCause", SSIncompatibilityCauseCodec()),
		"MAP-ER-DataTypes.PW-RegistrationFailureCause":           newMacroType("MAP-ER-DataTypes", "PW-RegistrationFailureCause", "PWRegistrationFailureCause", PWRegistrationFailureCauseCodec()),
		"MAP-ER-DataTypes.SM-DeliveryFailureCause":               newMacroType("MAP-ER-DataTypes", "SM-DeliveryFailureCause", "SMDeliveryFailureCause", SMDeliveryFailureCauseCodec()),
		"MAP-ER-DataTypes.SM-EnumeratedDeliveryFailureCause":     newMacroType("MAP-ER-DataTypes", "SM-EnumeratedDeliveryFailureCause", "SMEnumeratedDeliveryFailureCause", SMEnumeratedDeliveryFailureCauseCodec()),
		"MAP-ER-DataTypes.SM-DeliveryFailureCauseWithDiagnostic": newMacroType("MAP-ER-DataTypes", "SM-DeliveryFailureCauseWithDiagnostic", "SMDeliveryFailureCauseWithDiagnostic", SMDeliveryFailureCauseWithDiagnosticCodec()),
		"MAP-MS-DataTypes.UpdateLocationArg":                     newMacroType("MAP-MS-DataTypes", "UpdateLocationArg", "UpdateLocationArg", UpdateLocationArgCodec()),
		"MAP-MS-DataTypes.UpdateLocationRes":                     newMacroType("MAP-MS-DataTypes", "UpdateLocationRes", "UpdateLocationRes", UpdateLocationResCodec()),
		"MAP-MS-DataTypes.ExtensibleUpdateLocationRes":           newMacroType("MAP-MS-DataTypes", "ExtensibleUpdateLocationRes", "ExtensibleUpdateLocationRes", ExtensibleUpdateLocationResCodec()),
		"MAP-MS-DataTypes.CancelLocationArg":                     newMacroType("MAP-MS-DataTypes", "CancelLocationArg", "CancelLocationArg", CancelLocationArgCodec()),
		"MAP-MS-DataTypes.PurgeMS-Arg":                           newMacroType("MAP-MS-DataTypes", "PurgeMS-Arg", "PurgeMSArg", PurgeMSArgCodec()),
		"MAP-MS-DataTypes.IMSI-WithLMSI":                         newMacroType("MAP-MS-DataTypes", "IMSI-WithLMSI", "IMSIWithLMSI", IMSIWithLMSICodec()),
		"MAP-MS-DataTypes.SendIdentificationRes":                 newMacroType("MAP-MS-DataTypes", "SendIdentificationRes", "SendIdentificationRes", SendIdentificationResCodec()),
		"MAP-MS-DataTypes.AuthenticationSetList":                 newMacroType("MAP-MS-DataTypes", "AuthenticationSetList", "AuthenticationSetList", AuthenticationSetListCodec()),
		"MAP-MS-DataTypes.AuthenticationSet":                     newMacroType("MAP-MS-DataTypes", "AuthenticationSet", "AuthenticationSet", AuthenticationSetCodec()),
		"MAP-MS-DataTypes.RAND":                                  newMacroType("MAP-MS-DataTypes", "RAND", "RAND", RANDCodec()),
		"MAP-MS-DataTypes.SRES":                                  newMacroType("MAP-MS-DataTypes", "SRES", "SRES", SRESCodec()),
		"MAP-MS-DataTypes.Kc":                                    newMacroType("MAP-MS-DataTypes", "Kc", "Kc", KcCodec()),
		"MAP-MS-DataTypes.PrepareHO-Arg":                         newMacroType("MAP-MS-DataTypes", "PrepareHO-Arg", "PrepareHOArg", PrepareHOArgCodec()),
		"MAP-MS-DataTypes.PerformHO-Arg":                         newMacroType("MAP-MS-DataTypes", "PerformHO-Arg", "PerformHOArg", PerformHOArgCodec()),
		"MAP-MS-DataTypes.ChannelType":                           newMacroType("MAP-MS-DataTypes", "ChannelType", "ChannelType", ChannelTypeCodec()),
		"MAP-MS-DataTypes.ClassmarkInfo":                         newMacroType("MAP-MS-DataTypes", "ClassmarkInfo", "ClassmarkInfo", ClassmarkInfoCodec()),
		"MAP-MS-DataTypes.HandoverPriority":                      newMacroType("MAP-MS-DataTypes", "HandoverPriority", "HandoverPriority", HandoverPriorityCodec()),
		"MAP-MS-DataTypes.PrepareHO-Res":                         newMacroType("MAP-MS-DataTypes", "PrepareHO-Res", "PrepareHORes", PrepareHOResCodec()),
		"MAP-MS-DataTypes.PerformHO-Res":                         newMacroType("MAP-MS-DataTypes", "PerformHO-Res", "PerformHORes", PerformHOResCodec()),
		"MAP-MS-DataTypes.PrepareSubsequentHO-Arg":               newMacroType("MAP-MS-DataTypes", "PrepareSubsequentHO-Arg", "PrepareSubsequentHOArg", PrepareSubsequentHOArgCodec()),
		"MAP-MS-DataTypes.PerformSubsequentHO-Arg":               newMacroType("MAP-MS-DataTypes", "PerformSubsequentHO-Arg", "PerformSubsequentHOArg", PerformSubsequentHOArgCodec()),
		"MAP-MS-DataTypes.SendAuthenticationInfoArg":             newMacroType("MAP-MS-DataTypes", "SendAuthenticationInfoArg", "SendAuthenticationInfoArg", SendAuthenticationInfoArgCodec()),
		"MAP-MS-DataTypes.SendAuthenticationInfoRes":             newMacroType("MAP-MS-DataTypes", "SendAuthenticationInfoRes", "SendAuthenticationInfoRes", SendAuthenticationInfoResCodec()),
		"MAP-MS-DataTypes.Ki":                                    newMacroType("MAP-MS-DataTypes", "Ki", "Ki", KiCodec()),
		"MAP-MS-DataTypes.EquipmentStatus":                       newMacroType("MAP-MS-DataTypes", "EquipmentStatus", "EquipmentStatus", EquipmentStatusCodec()),
		"MAP-MS-DataTypes.SendParametersArg":                     newMacroType("MAP-MS-DataTypes", "SendParametersArg", "SendParametersArg", SendParametersArgCodec()),
		"MAP-MS-DataTypes.RequestParameterList":                  newMacroType("MAP-MS-DataTypes", "RequestParameterList", "RequestParameterList", RequestParameterListCodec()),
		"MAP-MS-DataTypes.RequestParameter":                      newMacroType("MAP-MS-DataTypes", "RequestParameter", "RequestParameter", RequestParameterCodec()),
		"MAP-MS-DataTypes.SentParameterList":                     newMacroType("MAP-MS-DataTypes", "SentParameterList", "SentParameterList", SentParameterListCodec()),
		"MAP-MS-DataTypes.SentParameter":                         newMacroType("MAP-MS-DataTypes", "SentParameter", "SentParameter", SentParameterCodec()),
		"MAP-MS-DataTypes.InsertSubscriberDataArg":               newMacroType("MAP-MS-DataTypes", "InsertSubscriberDataArg", "InsertSubscriberDataArg", InsertSubscriberDataArgCodec()),
		"MAP-MS-DataTypes.SubscriberData":                        newMacroType("MAP-MS-DataTypes", "SubscriberData", "SubscriberData", SubscriberDataCodec()),
		"MAP-MS-DataTypes.SubscriberStatus":                      newMacroType("MAP-MS-DataTypes", "SubscriberStatus", "SubscriberStatus", SubscriberStatusCodec()),
		"MAP-MS-DataTypes.ODB-Data":                              newMacroType("MAP-MS-DataTypes", "ODB-Data", "ODBData", ODBDataCodec()),
		"MAP-MS-DataTypes.ODB-GeneralData":                       newMacroType("MAP-MS-DataTypes", "ODB-GeneralData", "ODBGeneralData", ODBGeneralDataCodec()),
		"MAP-MS-DataTypes.ODB-HPLMN-Data":                        newMacroType("MAP-MS-DataTypes", "ODB-HPLMN-Data", "ODBHPLMNData", ODBHPLMNDataCodec()),
		"MAP-MS-DataTypes.ZoneCodeList":                          newMacroType("MAP-MS-DataTypes", "ZoneCodeList", "ZoneCodeList", ZoneCodeListCodec()),
		"MAP-MS-DataTypes.ZoneCode":                              newMacroType("MAP-MS-DataTypes", "ZoneCode", "ZoneCode", ZoneCodeCodec()),
		"MAP-MS-DataTypes.InsertSubscriberDataRes":               newMacroType("MAP-MS-DataTypes", "InsertSubscriberDataRes", "InsertSubscriberDataRes", InsertSubscriberDataResCodec()),
		"MAP-MS-DataTypes.RegionalSubscriptionResponse":          newMacroType("MAP-MS-DataTypes", "RegionalSubscriptionResponse", "RegionalSubscriptionResponse", RegionalSubscriptionResponseCodec()),
		"MAP-MS-DataTypes.DeleteSubscriberDataArg":               newMacroType("MAP-MS-DataTypes", "DeleteSubscriberDataArg", "DeleteSubscriberDataArg", DeleteSubscriberDataArgCodec()),
		"MAP-MS-DataTypes.DeleteSubscriberDataRes":               newMacroType("MAP-MS-DataTypes", "DeleteSubscriberDataRes", "DeleteSubscriberDataRes", DeleteSubscriberDataResCodec()),
		"MAP-MS-DataTypes.ResetArg":                              newMacroType("MAP-MS-DataTypes", "ResetArg", "ResetArg", ResetArgCodec()),
		"MAP-MS-DataTypes.RestoreDataArg":                        newMacroType("MAP-MS-DataTypes", "RestoreDataArg", "RestoreDataArg", RestoreDataArgCodec()),
		"MAP-MS-DataTypes.RestoreDataRes":                        newMacroType("MAP-MS-DataTypes", "RestoreDataRes", "RestoreDataRes", RestoreDataResCodec()),
		"MAP-OM-DataTypes.ActivateTraceModeArg":                  newMacroType("MAP-OM-DataTypes", "ActivateTraceModeArg", "ActivateTraceModeArg", ActivateTraceModeArgCodec()),
		"MAP-OM-DataTypes.TraceReference":                        newMacroType("MAP-OM-DataTypes", "TraceReference", "TraceReference", TraceReferenceCodec()),
		"MAP-OM-DataTypes.TraceType":                             newMacroType("MAP-OM-DataTypes", "TraceType", "TraceType", TraceTypeCodec()),
		"MAP-OM-DataTypes.DeactivateTraceModeArg":                newMacroType("MAP-OM-DataTypes", "DeactivateTraceModeArg", "DeactivateTraceModeArg", DeactivateTraceModeArgCodec()),
		"MAP-OM-DataTypes.TraceSubscriberActivityArg":            newMacroType("MAP-OM-DataTypes", "TraceSubscriberActivityArg", "TraceSubscriberActivityArg", TraceSubscriberActivityArgCodec()),
		"MAP-OM-DataTypes.CallReference":                         newMacroType("MAP-OM-DataTypes", "CallReference", "CallReference", CallReferenceCodec()),
		"MAP-OM-DataTypes.NoteInternalHO-Arg":                    newMacroType("MAP-OM-DataTypes", "NoteInternalHO-Arg", "NoteInternalHOArg", NoteInternalHOArgCodec()),
		"MAP-OM-DataTypes.HandoverType":                          newMacroType("MAP-OM-DataTypes", "HandoverType", "HandoverType", HandoverTypeCodec()),
		"MAP-SM-DataTypes.RoutingInfoForSM-Arg":                  newMacroType("MAP-SM-DataTypes", "RoutingInfoForSM-Arg", "RoutingInfoForSMArg", RoutingInfoForSMArgCodec()),
		"MAP-SM-DataTypes.RoutingInfoForSM-Res":                  newMacroType("MAP-SM-DataTypes", "RoutingInfoForSM-Res", "RoutingInfoForSMRes", RoutingInfoForSMResCodec()),
		"MAP-SM-DataTypes.LocationInfoWithLMSI":                  newMacroType("MAP-SM-DataTypes", "LocationInfoWithLMSI", "LocationInfoWithLMSI", LocationInfoWithLMSICodec()),
		"MAP-SM-DataTypes.ForwardSM-Arg":                         newMacroType("MAP-SM-DataTypes", "ForwardSM-Arg", "ForwardSMArg", ForwardSMArgCodec()),
		"MAP-SM-DataTypes.SM-RP-DA":                              newMacroType("MAP-SM-DataTypes", "SM-RP-DA", "SMRPDA", SMRPDACodec()),
		"MAP-SM-DataTypes.SM-RP-OA":                              newMacroType("MAP-SM-DataTypes", "SM-RP-OA", "SMRPOA", SMRPOACodec()),
		"MAP-SM-DataTypes.ReportSM-DeliveryStatusArg":            newMacroType("MAP-SM-DataTypes", "ReportSM-DeliveryStatusArg", "ReportSMDeliveryStatusArg", ReportSMDeliveryStatusArgCodec()),
		"MAP-SM-DataTypes.SM-DeliveryOutcome":                    newMacroType("MAP-SM-DataTypes", "SM-DeliveryOutcome", "SMDeliveryOutcome", SMDeliveryOutcomeCodec()),
		"MAP-SM-DataTypes.AlertServiceCentreArg":                 newMacroType("MAP-SM-DataTypes", "AlertServiceCentreArg", "AlertServiceCentreArg", AlertServiceCentreArgCodec()),
		"MAP-SM-DataTypes.InformServiceCentreArg":                newMacroType("MAP-SM-DataTypes", "InformServiceCentreArg", "InformServiceCentreArg", InformServiceCentreArgCodec()),
		"MAP-SM-DataTypes.MW-Status":                             newMacroType("MAP-SM-DataTypes", "MW-Status", "MWStatus", MWStatusCodec()),
		"MAP-SM-DataTypes.ReadyForSM-Arg":                        newMacroType("MAP-SM-DataTypes", "ReadyForSM-Arg", "ReadyForSMArg", ReadyForSMArgCodec()),
		"MAP-SM-DataTypes.AlertReason":                           newMacroType("MAP-SM-DataTypes", "AlertReason", "AlertReason", AlertReasonCodec()),
	}
}
