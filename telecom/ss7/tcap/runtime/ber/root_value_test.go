// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/root_value_test.go; SHA-256 c8140891e13c8e36217bbd274ca38323fe51688b08d29f0b2cfe1cbaac651a65.
package ber

import (
	"errors"
	"reflect"
	"testing"
)

func TestRootValueContext(t *testing.T) {
	const assignment = "Invoke-linkedId"
	const source = "Remote-Operations-Generic-ROS-PDUs.Invoke-linkedId"
	for _, nested := range []bool{false, true} {
		var d []DecodeOption
		var e []EncodeOption
		path := assignment
		encodedSource := source
		if nested {
			d = ChildDecodeOptions(d, "linkedId")
			e = ChildEncodeOptions(e, "linkedId")
			path = "linkedId"
			encodedSource = "Remote-Operations-Generic-ROS-PDUs.Invoke.linkedId"
		}
		d = LocateDecodedElement([]byte{0x81, 0}, source, d)
		e = EncodeSource(e, "Remote-Operations-Generic-ROS-PDUs.Invoke.linkedId")
		for _, row := range []struct {
			err    error
			source string
		}{
			{CheckDecodedRootValue(d, assignment, "Q.773 §4.2.2.2: component-id-linked-present", "NULL"), source},
			{CheckEncodedRootValue(e, assignment, source, "Q.773 §4.2.2.2: component-id-linked-present", "NULL"), encodedSource},
		} {
			var v *ValidationError
			if !errors.As(row.err, &v) || v.Path != path || v.Source != row.source {
				t.Fatalf("nested %t: %v %+v", nested, row.err, v)
			}
		}
	}
}

func TestValidationErrorMethodSet(t *testing.T) {
	for _, name := range []string{"rootValue", "nestedSource"} {
		if _, ok := reflect.TypeFor[Violation]().FieldByName(name); ok {
			t.Fatalf("private naming state: %s", name)
		}
	}
	typ := reflect.TypeFor[*ValidationError]()
	if typ.NumMethod() != 2 {
		t.Fatalf("ValidationError methods: %v", typ.NumMethod())
	}
	for _, name := range []string{"Error", "Unwrap"} {
		if _, ok := typ.MethodByName(name); !ok {
			t.Fatal(name)
		}
	}
}

func TestSourceFieldExactAssignment(t *testing.T) {
	for _, row := range []struct{ source, field, want string }{
		{"UnidialoguePDUs.UniDialoguePDU", "unidialoguePDU", "UnidialoguePDUs.UniDialoguePDU.unidialoguePDU"},
		{"Module.Named-type", "Namedtype", "Module.Named-type.Namedtype"},
		{"Module.Named-type", "Named-type", "Module.Named-type"},
		{"Module.Named-type", "", "Module.Named-type"},
	} {
		if got := sourceField(row.source, row.field); got != row.want {
			t.Fatalf("sourceField(%q,%q)=%q, want %q", row.source, row.field, got, row.want)
		}
	}
}
