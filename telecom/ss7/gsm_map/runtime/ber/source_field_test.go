// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/source_field_test.go; SHA-256 05ccfd5490c46697de4eb5de688c1c10493a24f4ea342caf9944f02c17f23bcf.
package ber

import "testing"

func TestSourceFieldExactAssignment(t *testing.T) {
	for _, tc := range []struct{ name, source, field, want string }{
		{"no source", "", "rows", ""},
		{"root", "Module.Sized-Rows", "Sized-Rows", "Module.Sized-Rows"},
		{"empty field", "Module.Rows", "", "Module.Rows"},
		{"nested component", "Module.Parent.child", "leaf", "Module.Parent.child.leaf"},
		{"case differs", "Module.Rows", "rows", "Module.Rows.rows"},
		{"hyphen differs", "Module.Sized-Rows", "SizedRows", "Module.Sized-Rows.SizedRows"},
		{"case and hyphen differ", "Module.Sized-Rows", "sizedRows", "Module.Sized-Rows.sizedRows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceField(tc.source, tc.field); got != tc.want {
				t.Fatalf("sourceField(%q, %q) = %q; want %q", tc.source, tc.field, got, tc.want)
			}
		})
	}
}
