// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/root_value.go; SHA-256 6da057bee3a3d52d463c831771a96a0a1604c945a3c012bb16117fee04ff8c3d.
package ber

// CheckDecodedRootValue names a standalone assignment's value-rule failure.
// A nested call retains its containing component path and located source.
// Like CheckDecodedValue, this is called only after a generated check fails.
func CheckDecodedRootValue(options []DecodeOption, assignment, constraint, observed string) error {
	config, err := decodeOptions(options)
	if err != nil {
		return err
	}
	if config.hasPath {
		assignment = ""
		if location := config.location; location != nil && location.parent != nil {
			// X.680 (02/2021) §16: a nested root rule is anchored at
			// the assignment declaring the containing component.
			copyLocation := *location
			copyLocation.source = sourceField(location.parent.source, location.parent.field)
			options = append(options[:len(options):len(options)], decodeLocationOption{&copyLocation})
		}
	}
	return CheckDecodedValue(options, assignment, constraint, observed)
}

// CheckEncodedRootValue names a standalone assignment's value-rule failure
// and retains the containing component's source for nested calls.
// It changes diagnostic metadata only, after a generated check has failed.
func CheckEncodedRootValue(options []EncodeOption, assignment, source, constraint, observed string) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if config.hasPath {
		assignment = ""
		source = config.source
	}
	return CheckEncodedValue(EncodeSource(options, source), assignment, constraint, observed)
}
