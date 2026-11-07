// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/encode_options.go; SHA-256 95891091478b100eda6cbd9a3bceaf553345af8ca0422816ca0065fedf0e8aa2.
package ber

import (
	"fmt"
)

type withoutBERReplayOption struct{}

func (withoutBERReplayOption) applyEncode(config *encodeConfig) error {
	config.noReplay = true
	return nil
}

// WithoutBERReplay makes generated BER encoders encode current typed values
// instead of replaying received forms, recursively including all children.
// Repeating this option is harmless. The default retains byte-exact replay
// for unchanged values. X.690 (02/2021) §§8.1.3 and 8.7.3 allow alternative
// length forms and constructed strings for the same abstract value.
//
// The TCAP package's generated encoders copy opaque open-type values only if
// they pass its canonical-payload element checks; values needing repair
// require a typed binding. Its dialogue encoder writes an unrecognized
// dialogue EXTERNAL with EncodeExternalDER. These generic checks do not
// establish DER conformance for a foreign schema. This package's own helpers
// keep refusing opaque copies under this option: CheckBEROpaqueReplay
// returns an error, and EncodeExternal refuses an opaque single-ASN1-type.
// Generated encoders apply the canonical-payload checks before copying and
// forward the options to every child and preservation helper.
// Typed primitive encoders must also skip separate received-form provenance,
// such as a BOOLEAN raw octet. Lexical text that is the current typed value
// is encoded as that value; this option does not normalize its spelling.
//
// This option does not enable constraint tolerance, make all typed output DER,
// or guarantee conformance with a protocol-specific BER profile. Typed output
// retains explicitly present DEFAULT components, including non-nil pointers
// populated by decoding (X.690 (02/2021) §8.9.3). Only DER and CER omit a
// DEFAULT-equal component (§11.5). Explicit constraint tolerance still
// permits values outside their ASN.1 subtype and reports those violations.
func WithoutBERReplay() EncodeOption { return withoutBERReplayOption{} }

// BERReplayEnabled reports whether valid encode options permit replay of a
// typed value's retained BER form. Both comparison streams must use the same
// generated BER form; X.690 (02/2021) §8.1.3 permits alternate length forms.
// A strict operation also disables envelope and EXTERNAL copies after an edit when its
// decode retained a violation: value equality does not establish the received
// form complies with Q.773 (06/1997) §4.1.1. Tolerant replay remains available.
// Malformed options return false; generated entry points must still reject
// them with ValidateEncodeOptions.
func BERReplayEnabled(options []EncodeOption) bool {
	config, err := encodeOptions(options)
	if err != nil || config.noReplay {
		return false
	}
	for _, option := range options {
		if mode, ok := option.(replayModeOption); ok {
			if mode.collector != nil || mode.comparison || !config.tolerant && mode.rebuildChildren {
				return false
			}
		}
	}
	return true
}

// CheckBEROpaqueReplay rejects copying any present opaque open-type value or
// unknown extension when WithoutBERReplay is requested. The error wraps
// ErrInvalidValue; constraint tolerance cannot override it. A caller must
// supply a known typed value to encode it under that policy. The TCAP
// package's generated encoders instead copy an element that passes their
// canonical-payload checks.
//
// In default mode this helper only validates options. It does not validate
// the opaque bytes: encoders must separately require a complete encoding of
// one value (X.690 (02/2021) §8.15), including the appropriate BER/DER rules.
func CheckBEROpaqueReplay(options ...EncodeOption) error {
	config, err := encodeOptions(options)
	if err != nil {
		return err
	}
	if config.noReplay {
		return fmt.Errorf("%w: BER replay disabled for opaque open value or unknown extension; a typed value is required", ErrInvalidValue)
	}
	return nil
}
